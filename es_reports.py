#!/usr/bin/env python3
"""Generate and index daily/weekly/monthly reports from Cowrie data to Elasticsearch.

This tool reads from the SQLite database populated by process_cowrie.py and generates
aggregated reports for Elasticsearch, supporting multi-sensor deployments.
"""

import argparse
import json
import logging
import os
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, cast

from elasticsearch import Elasticsearch

from secrets_resolver import is_reference, resolve_secret

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CowrieReporter:
    """Generate Elasticsearch reports from Cowrie SQLite data."""

    def __init__(
        self,
        db_path: str = "../cowrieprocessor.sqlite",
        es_host: Optional[str] = None,
        es_username: Optional[str] = None,
        es_password: Optional[str] = None,
        es_api_key: Optional[str] = None,
        es_cloud_id: Optional[str] = None,
        es_verify_ssl: bool = True,
        sensor_name: Optional[str] = None,
        top_n: int = 10,
        vt_recent_days: int = 5,
        timezone_str: str = "UTC",
    ):
        """Initialize reporter with database and Elasticsearch connections.

        Args:
            db_path: Path to SQLite database
            es_host: Elasticsearch host URL
            es_username: Basic auth username
            es_password: Basic auth password
            es_api_key: API key for authentication
            es_cloud_id: Elastic Cloud ID
            es_verify_ssl: Verify SSL certificates
            sensor_name: Override sensor name (default: hostname)
            top_n: Number of top items to include in reports
            vt_recent_days: Days to consider VT submission "recent"
            timezone_str: Timezone for date boundaries (default: UTC)
        """
        self.db_path = db_path
        self.top_n = top_n
        self.vt_recent_days = vt_recent_days
        self.timezone = timezone_str
        self.sensor_name = sensor_name or os.uname().nodename

        # Connect to SQLite
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute('PRAGMA busy_timeout=5000')
        except Exception:
            pass

        # Connect to Elasticsearch
        es_config: Dict[str, Any] = {}
        if es_cloud_id:
            es_config['cloud_id'] = es_cloud_id
        elif es_host:
            es_config['hosts'] = [es_host]
        else:
            raise ValueError("Either es_host or es_cloud_id must be provided")

        if es_api_key:
            es_config['api_key'] = es_api_key
        elif es_username and es_password:
            es_config['basic_auth'] = (es_username, es_password)

        es_config['verify_certs'] = es_verify_ssl

        self.es = Elasticsearch(**es_config)

        # Verify connection
        if not self.es.ping():
            raise ConnectionError("Cannot connect to Elasticsearch")

        logger.info("Connected to Elasticsearch and SQLite database")

    def _get_top_n(self, items: List[Any], n: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get top N items with counts from a list."""
        if not items:
            return []
        n = n or self.top_n
        counter = Counter(items)
        return [{"value": k, "count": v} for k, v in counter.most_common(n)]

    def _get_date_range(self, date_utc: str) -> Tuple[int, int]:
        """Convert date string to epoch timestamps for day boundaries."""
        dt = datetime.strptime(date_utc, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        start_epoch = int(dt.timestamp())
        end_epoch = int((dt + timedelta(days=1)).timestamp())
        return start_epoch, end_epoch

    def generate_daily_report(self, date_utc: str, sensor: Optional[str] = None) -> Dict[str, Any]:
        """Generate daily report for a specific sensor or aggregate.

        Args:
            date_utc: Date in YYYY-MM-DD format
            sensor: Specific sensor name, or None for aggregate

        Returns:
            Report document ready for indexing
        """
        start_epoch, end_epoch = self._get_date_range(date_utc)

        # Build sensor filter
        sensor_filter = ""
        params: List[Any] = [start_epoch, end_epoch]
        if sensor:
            sensor_filter = " AND hostname = ?"
            params.append(sensor)

        # Initialize report structure
        report: Dict[str, Any] = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "date_utc": date_utc,
            "sensor": sensor or "aggregate",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "report_type": "daily",
            "sessions": {},
            "commands": {},
            "files": {},
            "enrichments": {},
            "abnormalities": {},
            "alerts": [],
        }

        # Query sessions
        cur = self.conn.cursor()

        # Basic session metrics
        query = f"""
            SELECT 
                COUNT(DISTINCT session) as total_sessions,
                COUNT(DISTINCT source_ip) as unique_ips,
                COUNT(DISTINCT username) as unique_usernames,
                COUNT(DISTINCT password) as unique_passwords,
                AVG(total_commands) as avg_commands,
                MAX(total_commands) as max_commands,
                MIN(total_commands) as min_commands,
                AVG(session_duration) as avg_duration
            FROM sessions 
            WHERE timestamp >= ? AND timestamp < ?{sensor_filter}
        """

        cur.execute(query, tuple(params))
        row = cur.fetchone()

        report['sessions'] = {
            'total': row['total_sessions'] or 0,
            'unique_ips': row['unique_ips'] or 0,
            'unique_usernames': row['unique_usernames'] or 0,
            'unique_passwords': row['unique_passwords'] or 0,
            'avg_commands': round(row['avg_commands'] or 0, 2),
            'max_commands': row['max_commands'] or 0,
            'min_commands': row['min_commands'] or 0,
            'avg_duration': round(row['avg_duration'] or 0, 2),
        }

        # Protocol breakdown
        query = f"""
            SELECT protocol, COUNT(*) as count
            FROM sessions
            WHERE timestamp >= ? AND timestamp < ?{sensor_filter}
            GROUP BY protocol
        """
        cur.execute(query, tuple(params))
        protocols: Dict[str, int] = {}
        for row in cur.fetchall():
            if row['protocol']:
                protocols[row['protocol']] = row['count']
        report['sessions']['protocols'] = protocols

        # Top usernames, passwords, and combinations
        query = f"""
            SELECT username, COUNT(*) as count
            FROM sessions
            WHERE timestamp >= ? AND timestamp < ?{sensor_filter}
            GROUP BY username
            ORDER BY count DESC
            LIMIT ?
        """
        cur.execute(query, (*tuple(params), self.top_n))
        report['sessions']['top_usernames'] = [
            {"value": row['username'], "count": row['count']} for row in cur.fetchall() if row['username']
        ]

        query = f"""
            SELECT password, COUNT(*) as count
            FROM sessions
            WHERE timestamp >= ? AND timestamp < ?{sensor_filter}
            GROUP BY password
            ORDER BY count DESC
            LIMIT ?
        """
        cur.execute(query, (*tuple(params), self.top_n))
        report['sessions']['top_passwords'] = [
            {"value": row['password'], "count": row['count']} for row in cur.fetchall() if row['password']
        ]

        query = f"""
            SELECT username || ':' || password as combo, COUNT(*) as count
            FROM sessions
            WHERE timestamp >= ? AND timestamp < ?{sensor_filter}
            GROUP BY username, password
            ORDER BY count DESC
            LIMIT ?
        """
        cur.execute(query, (*tuple(params), self.top_n))
        report['sessions']['top_combinations'] = [
            {"value": row['combo'], "count": row['count']} for row in cur.fetchall() if row['combo']
        ]

        # Command statistics
        query = f"""
            SELECT 
                COUNT(*) as total_commands,
                COUNT(DISTINCT command) as unique_commands
            FROM commands c
            JOIN sessions s ON c.session = s.session
            WHERE s.timestamp >= ? AND s.timestamp < ?{(' AND s.hostname = ?' if sensor else '')}
        """
        cur.execute(query, tuple(params))
        row = cur.fetchone()

        report['commands'] = {'total': row['total_commands'] or 0, 'unique': row['unique_commands'] or 0}

        # Top commands
        query = f"""
            SELECT command, COUNT(*) as count
            FROM commands c
            JOIN sessions s ON c.session = s.session
            WHERE s.timestamp >= ? AND s.timestamp < ?{(' AND s.hostname = ?' if sensor else '')}
            GROUP BY command
            ORDER BY count DESC
            LIMIT ?
        """
        cur.execute(query, (*tuple(params), self.top_n))
        report['commands']['top_commands'] = [
            {"value": row['command'], "count": row['count']} for row in cur.fetchall() if row['command']
        ]

        # File activity
        query = f"""
            SELECT 
                COUNT(CASE WHEN transfer_method = 'DOWNLOAD' THEN 1 END) as downloads,
                COUNT(CASE WHEN transfer_method = 'UPLOAD' THEN 1 END) as uploads,
                COUNT(DISTINCT hash) as unique_hashes,
                COUNT(DISTINCT vt_threat_classification) as unique_vt_classifications
            FROM files f
            JOIN sessions s ON f.session = s.session
            WHERE s.timestamp >= ? AND s.timestamp < ?{(' AND s.hostname = ?' if sensor else '')}
        """
        cur.execute(query, tuple(params))
        row = cur.fetchone()

        report['files'] = {
            'downloads_total': row['downloads'] or 0,
            'uploads_total': row['uploads'] or 0,
            'unique_hashes': row['unique_hashes'] or 0,
            'unique_vt_classifications': row['unique_vt_classifications'] or 0,
        }

        # VT classifications breakdown
        query = f"""
            SELECT vt_threat_classification, COUNT(*) as count
            FROM files f
            JOIN sessions s ON f.session = s.session
            WHERE s.timestamp >= ? AND s.timestamp < ?{(' AND s.hostname = ?' if sensor else '')}
            AND vt_threat_classification IS NOT NULL
            GROUP BY vt_threat_classification
            ORDER BY count DESC
            LIMIT ?
        """
        cur.execute(query, (*tuple(params), self.top_n))
        report['files']['vt_classifications_top'] = [
            {"value": row['vt_threat_classification'], "count": row['count']}
            for row in cur.fetchall()
            if row['vt_threat_classification']
        ]

        # Recent VT submissions
        recent_cutoff = int((datetime.utcnow() - timedelta(days=self.vt_recent_days)).timestamp())
        query = """
            SELECT COUNT(DISTINCT f.session) as recent_sessions
            FROM files f
            JOIN sessions s ON f.session = s.session
            WHERE s.timestamp >= ? AND s.timestamp < ?
            AND f.vt_first_submission >= ?
        """
        cur.execute(query, (*tuple(params), recent_cutoff))
        row = cur.fetchone()
        report['files']['recent_vt_submissions'] = row['recent_sessions'] or 0

        # Top file hashes
        query = f"""
            SELECT hash, COUNT(*) as count
            FROM files f
            JOIN sessions s ON f.session = s.session
            WHERE s.timestamp >= ? AND s.timestamp < ?{(' AND s.hostname = ?' if sensor else '')}
            GROUP BY hash
            ORDER BY count DESC
            LIMIT ?
        """
        cur.execute(query, (*tuple(params), self.top_n))
        report['files']['top_hashes'] = [
            {"value": row['hash'][:16] + "...", "count": row['count']} for row in cur.fetchall() if row['hash']
        ]

        # Enrichment data (URLhaus, ASN, Country, SPUR)

        # URLhaus tags
        query = f"""
            SELECT urlhaus_tag
            FROM sessions
            WHERE timestamp >= ? AND timestamp < ?{sensor_filter}
            AND urlhaus_tag IS NOT NULL AND urlhaus_tag != ''
        """
        cur.execute(query, tuple(params))
        all_tags: List[str] = []
        for row in cur.fetchall():
            if row['urlhaus_tag']:
                all_tags.extend([t.strip() for t in row['urlhaus_tag'].split(',')])
        report['enrichments']['urlhaus_tags_top'] = self._get_top_n(all_tags)

        # Top ASNs
        query = f"""
            SELECT asname, COUNT(*) as count
            FROM sessions
            WHERE timestamp >= ? AND timestamp < ?{sensor_filter}
            AND asname IS NOT NULL
            GROUP BY asname
            ORDER BY count DESC
            LIMIT ?
        """
        cur.execute(query, (*tuple(params), self.top_n))
        report['enrichments']['asn_top'] = [
            {"value": row['asname'], "count": row['count']} for row in cur.fetchall() if row['asname']
        ]

        # Top countries
        query = f"""
            SELECT ascountry, COUNT(*) as count
            FROM sessions
            WHERE timestamp >= ? AND timestamp < ?{sensor_filter}
            AND ascountry IS NOT NULL
            GROUP BY ascountry
            ORDER BY count DESC
            LIMIT ?
        """
        cur.execute(query, (*tuple(params), self.top_n))
        report['enrichments']['country_top'] = [
            {"value": row['ascountry'], "count": row['count']} for row in cur.fetchall() if row['ascountry']
        ]

        # SPUR infrastructure types
        query = f"""
            SELECT spur_infrastructure, COUNT(*) as count
            FROM sessions
            WHERE timestamp >= ? AND timestamp < ?{sensor_filter}
            AND spur_infrastructure IS NOT NULL AND spur_infrastructure != ''
            GROUP BY spur_infrastructure
            ORDER BY count DESC
            LIMIT ?
        """
        cur.execute(query, (*tuple(params), self.top_n))
        report['enrichments']['spur_infrastructure_top'] = [
            {"value": row['spur_infrastructure'], "count": row['count']}
            for row in cur.fetchall()
            if row['spur_infrastructure']
        ]

        # SPUR tunnel usage
        query = f"""
            SELECT 
                COUNT(CASE WHEN spur_tunnel_type IS NOT NULL AND spur_tunnel_type != '' THEN 1 END) as tunnel_sessions,
                COUNT(CASE WHEN spur_tunnel_anonymous = 'true' THEN 1 END) as anonymous_tunnels
            FROM sessions
            WHERE timestamp >= ? AND timestamp < ?{sensor_filter}
        """
        cur.execute(query, tuple(params))
        row = cur.fetchone()
        report['enrichments']['spur_tunnels'] = {
            'total': row['tunnel_sessions'] or 0,
            'anonymous': row['anonymous_tunnels'] or 0,
        }

        # Abnormality detection (based on process_cowrie.py logic)

        # Get command count distribution for anomaly detection
        query = f"""
            SELECT total_commands, COUNT(*) as session_count
            FROM sessions
            WHERE timestamp >= ? AND timestamp < ?{sensor_filter}
            GROUP BY total_commands
            ORDER BY session_count DESC
        """
        cur.execute(query, tuple(params))
        command_distribution = list(cur.fetchall())

        if command_distribution:
            # Find uncommon command counts (bottom 2/3 by frequency)
            sorted_counts = sorted(command_distribution, key=lambda x: x['session_count'])
            threshold_idx = int(len(sorted_counts) * 2 / 3)
            uncommon_counts = set(row['total_commands'] for row in sorted_counts[:threshold_idx])

            # Count sessions with uncommon command counts
            query = f"""
                SELECT COUNT(DISTINCT session) as count
                FROM sessions
                WHERE timestamp >= ? AND timestamp < ?{sensor_filter}
                AND total_commands IN ({','.join('?' * len(uncommon_counts))})
            """
            if uncommon_counts:
                cur.execute(query, (*tuple(params), *uncommon_counts))
                row = cur.fetchone()
                report['abnormalities']['uncommon_command_sessions'] = row['count'] or 0
            else:
                report['abnormalities']['uncommon_command_sessions'] = 0
        else:
            report['abnormalities']['uncommon_command_sessions'] = 0

        # Sessions with recent VT submissions
        report['abnormalities']['recent_vt_submission_sessions'] = report['files']['recent_vt_submissions']

        # Alert generation
        alerts: List[Dict[str, Any]] = []

        # Alert: Spike in unique IPs (>50% increase from 7-day average)
        week_ago = (datetime.strptime(date_utc, "%Y-%m-%d") - timedelta(days=7)).strftime("%Y-%m-%d")
        query = f"""
            SELECT AVG(ip_count) as avg_ips FROM (
                SELECT COUNT(DISTINCT source_ip) as ip_count
                FROM sessions
                WHERE timestamp >= ? AND timestamp < ?{sensor_filter}
                GROUP BY timestamp / 86400
            )
        """
        week_start, _ = self._get_date_range(week_ago)
        cur.execute(query, (week_start, start_epoch, *([sensor] if sensor else [])))
        row = cur.fetchone()
        avg_ips = row['avg_ips'] or 0

        if avg_ips > 0 and report['sessions']['unique_ips'] > avg_ips * 1.5:
            pct_increase = int((report['sessions']['unique_ips'] / avg_ips - 1) * 100)
            msg = f"Unique IPs increased by {pct_increase}% from 7-day average"
            alerts.append(
                {
                    "type": "ip_spike",
                    "severity": "medium",
                    "message": msg,
                    "current": report['sessions']['unique_ips'],
                    "average": round(avg_ips, 2),
                }
            )

        # Alert: New VT classification not seen in past 30 days
        if report['files']['vt_classifications_top']:
            month_ago = (datetime.strptime(date_utc, "%Y-%m-%d") - timedelta(days=30)).strftime("%Y-%m-%d")
            month_start, _ = self._get_date_range(month_ago)

            query = f"""
                SELECT DISTINCT vt_threat_classification
                FROM files f
                JOIN sessions s ON f.session = s.session
                WHERE s.timestamp >= ? AND s.timestamp < ?{(' AND s.hostname = ?' if sensor else '')}
                AND vt_threat_classification IS NOT NULL
            """
            cur.execute(query, (month_start, start_epoch, *([sensor] if sensor else [])))
            past_classifications = set(row['vt_threat_classification'] for row in cur.fetchall())

            cur.execute(query, tuple(params))
            today_classifications = set(row['vt_threat_classification'] for row in cur.fetchall())

            new_classifications = today_classifications - past_classifications
            if new_classifications:
                alerts.append(
                    {
                        "type": "new_vt_classification",
                        "severity": "high",
                        "message": f"New VT classifications detected: {', '.join(new_classifications)}",
                        "classifications": list(new_classifications),
                    }
                )

        # Alert: High percentage of tunneled traffic
        if report['sessions']['total'] > 0:
            tunnel_pct = (report['enrichments']['spur_tunnels']['total'] / report['sessions']['total']) * 100
            if tunnel_pct > 30:  # More than 30% tunneled
                alerts.append(
                    {
                        "type": "high_tunnel_usage",
                        "severity": "medium",
                        "message": f"{tunnel_pct:.1f}% of sessions using tunnels/proxies",
                        "percentage": round(tunnel_pct, 2),
                    }
                )

        report['alerts'] = alerts

        cur.close()
        return report

    def index_report(self, report: Dict[str, Any], index_pattern: str = "cowrie.reports.daily-write") -> bool:
        """Index a report document to Elasticsearch.

        Args:
            report: Report document
            index_pattern: Index pattern to use

        Returns:
            Success status
        """
        # Always write to the ILM write alias. If a base name was provided, append -write.
        index_alias = index_pattern if index_pattern.endswith('-write') else f"{index_pattern}-write"
        doc_id = f"{report['sensor']}:{report['date_utc']}"

        try:
            self.es.index(index=index_alias, id=doc_id, document=report)
            logger.info(f"Indexed report {doc_id} to {index_alias}")
            return True
        except Exception as e:
            logger.error(f"Failed to index report {doc_id}: {e}")
            return False

    def backfill_daily(self, start_date: str, end_date: str, sensors: Optional[List[str]] = None) -> None:
        """Backfill daily reports for a date range.

        Args:
            start_date: Start date (YYYY-MM-DD)
            end_date: End date (YYYY-MM-DD), inclusive
            sensors: List of sensors to process (None for all)
        """
        # Get list of sensors if not provided
        if not sensors:
            cur = self.conn.cursor()
            cur.execute("SELECT DISTINCT hostname FROM sessions WHERE hostname IS NOT NULL")
            sensors = [row['hostname'] for row in cur.fetchall()]
            cur.close()

        # Always include aggregate
        sensors_to_process: List[Optional[str]] = [*sensors, None]

        # Iterate through dates
        current = datetime.strptime(start_date, "%Y-%m-%d")
        end = datetime.strptime(end_date, "%Y-%m-%d")

        total_reports = 0
        failed_reports = 0

        while current <= end:
            date_str = current.strftime("%Y-%m-%d")
            logger.info(f"Processing {date_str}")

            for sensor in sensors_to_process:
                sensor_name = sensor or "aggregate"
                try:
                    report = self.generate_daily_report(date_str, sensor)
                    if self.index_report(report):
                        total_reports += 1
                    else:
                        failed_reports += 1
                except Exception as e:
                    logger.error(f"Failed to generate report for {sensor_name} on {date_str}: {e}")
                    failed_reports += 1

            current += timedelta(days=1)

        logger.info(f"Backfill complete: {total_reports} indexed, {failed_reports} failed")

    def generate_weekly_rollup(self, year_week: str) -> Optional[Dict[str, Any]]:
        """Generate weekly rollup from daily reports.

        Args:
            year_week: Year and week in YYYY-Www format

        Returns:
            Weekly rollup document
        """
        # Parse year and week
        year_s, week_s = year_week.split('-W')
        year_i = int(year_s)
        week_i = int(week_s)

        # Calculate date range for the week
        jan1 = datetime(year_i, 1, 1)
        week_start = jan1 + timedelta(days=(week_i - 1) * 7 - jan1.weekday())
        week_end = week_start + timedelta(days=6)

        # Query daily reports from Elasticsearch
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "date_utc": {
                                    "gte": week_start.strftime("%Y-%m-%d"),
                                    "lte": week_end.strftime("%Y-%m-%d"),
                                }
                            }
                        },
                        {"term": {"report_type": "daily"}},
                        {"term": {"sensor": "aggregate"}},
                    ]
                }
            },
            "size": 7,
        }

        response = self.es.search(index="cowrie.reports.daily-*", body=query)

        if not response['hits']['hits']:
            logger.warning(f"No daily reports found for week {year_week}")
            return None

        # Aggregate the daily reports
        weekly: Dict[str, Any] = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "year_week": year_week,
            "date_range": {"start": week_start.strftime("%Y-%m-%d"), "end": week_end.strftime("%Y-%m-%d")},
            "sensor": "aggregate",
            "report_type": "weekly",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "days_included": len(response['hits']['hits']),
            "sessions": defaultdict(int),
            "commands": defaultdict(int),
            "files": defaultdict(int),
            "enrichments": defaultdict(list),
            "alerts_summary": [],
        }

        # Sum up metrics from daily reports
        for hit in response['hits']['hits']:
            daily = cast(Dict[str, Any], hit['_source'])

            # Aggregate sessions
            for key in ['total', 'unique_ips', 'unique_usernames', 'unique_passwords']:
                if key in daily.get('sessions', {}):
                    weekly['sessions'][key] += daily['sessions'][key]

            # Aggregate commands
            for key in ['total', 'unique']:
                if key in daily.get('commands', {}):
                    weekly['commands'][key] += daily['commands'][key]

            # Aggregate files
            for key in ['downloads_total', 'uploads_total', 'unique_hashes']:
                if key in daily.get('files', {}):
                    weekly['files'][key] += daily['files'][key]

            # Collect all alerts
            if daily.get('alerts'):
                weekly['alerts_summary'].extend(daily['alerts'])

        # Convert defaultdicts to regular dicts
        weekly['sessions'] = dict(weekly['sessions'])
        weekly['commands'] = dict(weekly['commands'])
        weekly['files'] = dict(weekly['files'])

        # Calculate averages
        if weekly['days_included'] > 0:
            weekly['sessions']['daily_average'] = round(weekly['sessions']['total'] / weekly['days_included'], 2)
            weekly['commands']['daily_average'] = round(weekly['commands']['total'] / weekly['days_included'], 2)

        return weekly

    def generate_monthly_rollup(self, year_month: str) -> Optional[Dict[str, Any]]:
        """Generate monthly rollup from daily reports.

        Args:
            year_month: Year and month in YYYY-MM format
        Returns:
            Monthly rollup document or None if no data
        """
        year, month = map(int, year_month.split('-'))
        month_start = datetime(year, month, 1)
        if month == 12:
            month_end = datetime(year + 1, 1, 1) - timedelta(days=1)
        else:
            month_end = datetime(year, month + 1, 1) - timedelta(days=1)

        query = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "date_utc": {
                                    "gte": month_start.strftime("%Y-%m-%d"),
                                    "lte": month_end.strftime("%Y-%m-%d"),
                                }
                            }
                        },
                        {"term": {"report_type": "daily"}},
                        {"term": {"sensor": "aggregate"}},
                    ]
                }
            },
            "size": 31,
        }

        response = self.es.search(index="cowrie.reports.daily-*", body=query)
        hits = response.get('hits', {}).get('hits', [])
        if not hits:
            logger.warning(f"No daily reports found for month {year_month}")
            return None

        monthly: Dict[str, Any] = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "year_month": year_month,
            "date_range": {"start": month_start.strftime("%Y-%m-%d"), "end": month_end.strftime("%Y-%m-%d")},
            "sensor": "aggregate",
            "report_type": "monthly",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "days_included": len(hits),
            "sessions": defaultdict(int),
            "commands": defaultdict(int),
            "files": defaultdict(int),
            "enrichments": {
                "unique_vt_classifications": set(),
                "unique_urlhaus_tags": set(),
                "unique_countries": set(),
                "unique_asns": set(),
            },
            "alerts_summary": defaultdict(lambda: {"count": 0, "messages": []}),
        }

        for hit in hits:
            daily = cast(Dict[str, Any], hit['_source'])
            for key in ['total', 'unique_ips', 'unique_usernames', 'unique_passwords']:
                if key in daily.get('sessions', {}):
                    monthly['sessions'][key] += daily['sessions'][key]
            for key in ['total', 'unique']:
                if key in daily.get('commands', {}):
                    monthly['commands'][key] += daily['commands'][key]
            for key in ['downloads_total', 'uploads_total', 'unique_hashes', 'recent_vt_submissions']:
                if key in daily.get('files', {}):
                    monthly['files'][key] += daily['files'][key]

            for item in daily.get('files', {}).get('vt_classifications_top', []) or []:
                if item.get('value'):
                    monthly['enrichments']['unique_vt_classifications'].add(item['value'])
            for item in daily.get('enrichments', {}).get('urlhaus_tags_top', []) or []:
                if item.get('value'):
                    monthly['enrichments']['unique_urlhaus_tags'].add(item['value'])
            for item in daily.get('enrichments', {}).get('country_top', []) or []:
                if item.get('value'):
                    monthly['enrichments']['unique_countries'].add(item['value'])
            for item in daily.get('enrichments', {}).get('asn_top', []) or []:
                if item.get('value'):
                    monthly['enrichments']['unique_asns'].add(item['value'])

            for alert in daily.get('alerts', []) or []:
                alert_type = alert.get('type', 'unknown')
                monthly['alerts_summary'][alert_type]['count'] += 1
                monthly['alerts_summary'][alert_type]['messages'].append(
                    {"date": daily.get('date_utc'), "message": alert.get('message'), "severity": alert.get('severity')}
                )

        monthly['enrichments'] = {
            'unique_vt_classifications': len(monthly['enrichments']['unique_vt_classifications']),
            'unique_urlhaus_tags': len(monthly['enrichments']['unique_urlhaus_tags']),
            'unique_countries': len(monthly['enrichments']['unique_countries']),
            'unique_asns': len(monthly['enrichments']['unique_asns']),
        }
        monthly['sessions'] = dict(monthly['sessions'])
        monthly['commands'] = dict(monthly['commands'])
        monthly['files'] = dict(monthly['files'])
        monthly['alerts_summary'] = dict(monthly['alerts_summary'])

        if monthly['days_included'] > 0:
            monthly['sessions']['daily_average'] = round(monthly['sessions']['total'] / monthly['days_included'], 2)
            monthly['commands']['daily_average'] = round(monthly['commands']['total'] / monthly['days_included'], 2)
            monthly['files']['daily_average_downloads'] = round(
                monthly['files']['downloads_total'] / monthly['days_included'], 2
            )

        # Compare to previous month if available
        prev_month = month - 1 if month > 1 else 12
        prev_year = year if month > 1 else year - 1
        prev_month_str = f"{prev_year:04d}-{prev_month:02d}"

        prev_query = {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"year_month": prev_month_str}},
                        {"term": {"report_type": "monthly"}},
                        {"term": {"sensor": "aggregate"}},
                    ]
                }
            },
            "size": 1,
        }
        prev_response = self.es.search(index="cowrie.reports.monthly-*", body=prev_query, ignore=[404])
        prev_hits = prev_response.get('hits', {}).get('hits', [])
        if prev_hits:
            prev = cast(Dict[str, Any], prev_hits[0]['_source'])

            def pct_change(curr, prev_val):
                return round(((curr - prev_val) / prev_val * 100) if prev_val > 0 else 0, 2)

            sessions_curr = monthly['sessions'].get('total', 0)
            sessions_prev = prev.get('sessions', {}).get('total', 0)
            uniq_curr = monthly['sessions'].get('unique_ips', 0)
            uniq_prev = prev.get('sessions', {}).get('unique_ips', 0)
            files_curr = monthly['files'].get('downloads_total', 0)
            files_prev = prev.get('files', {}).get('downloads_total', 0)
            monthly['trends'] = {
                'sessions_change': pct_change(sessions_curr, sessions_prev),
                'unique_ips_change': pct_change(uniq_curr, uniq_prev),
                'files_change': pct_change(files_curr, files_prev),
            }

        return monthly

    def close(self):
        """Close database connections."""
        self.conn.close()
        self.es.close()


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description='Generate Elasticsearch reports from Cowrie data')

    # Database options
    parser.add_argument('--db', default='../cowrieprocessor.sqlite', help='Path to SQLite database')

    # Elasticsearch options
    parser.add_argument('--es-host', help='Elasticsearch host URL')
    parser.add_argument('--es-username', help='Elasticsearch username')
    parser.add_argument('--es-password', help='Elasticsearch password')
    parser.add_argument('--es-api-key', help='Elasticsearch API key')
    parser.add_argument('--es-cloud-id', help='Elastic Cloud ID')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL certificate verification')

    # Report options
    parser.add_argument('--sensor', help='Sensor name (default: hostname)')
    parser.add_argument('--top-n', type=int, default=10, help='Number of top items to include (default: 10)')
    parser.add_argument(
        '--vt-recent-days', type=int, default=5, help='Days to consider VT submission recent (default: 5)'
    )

    # Commands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Daily report command
    daily_parser = subparsers.add_parser('daily', help='Generate daily report')
    daily_parser.add_argument(
        '--date', default=datetime.utcnow().strftime('%Y-%m-%d'), help='Date to process (YYYY-MM-DD)'
    )
    daily_parser.add_argument('--all-sensors', action='store_true', help='Generate reports for all sensors')

    # Backfill command
    backfill_parser = subparsers.add_parser('backfill', help='Backfill reports for date range')
    backfill_parser.add_argument('--start', required=True, help='Start date (YYYY-MM-DD)')
    backfill_parser.add_argument('--end', required=True, help='End date (YYYY-MM-DD)')
    backfill_parser.add_argument('--sensors', nargs='*', help='Specific sensors to process')

    # Weekly rollup command
    weekly_parser = subparsers.add_parser('weekly', help='Generate weekly rollup')
    weekly_parser.add_argument(
        '--week', default=datetime.utcnow().strftime('%Y-W%U'), help='Week to process (YYYY-Www)'
    )

    # Monthly rollup command
    monthly_parser = subparsers.add_parser('monthly', help='Generate monthly rollup')
    monthly_parser.add_argument(
        '--month', default=datetime.utcnow().strftime('%Y-%m'), help='Month to process (YYYY-MM)'
    )

    args = parser.parse_args()

    # Get ES credentials from environment if not provided
    es_host = args.es_host or os.getenv('ES_HOST')
    es_username = args.es_username or os.getenv('ES_USERNAME')
    es_password = args.es_password or os.getenv('ES_PASSWORD')
    es_api_key = args.es_api_key or os.getenv('ES_API_KEY')
    # Resolve secret references if provided via env/args
    try:
        if is_reference(es_password):
            es_password = resolve_secret(es_password)
        if is_reference(es_api_key):
            es_api_key = resolve_secret(es_api_key)
    except Exception:
        # Keep silent on resolution failure; fallback to raw value
        pass
    es_cloud_id = args.es_cloud_id or os.getenv('ES_CLOUD_ID')
    # SSL verify from env (ES_VERIFY_SSL=false to disable)
    env_verify = os.getenv('ES_VERIFY_SSL')
    verify_ssl = True
    if args.no_ssl_verify:
        verify_ssl = False
    elif env_verify is not None and env_verify.lower() in ('false', '0', 'no'):
        verify_ssl = False

    if not (es_host or es_cloud_id):
        logger.error("Either ES_HOST or ES_CLOUD_ID must be provided")
        sys.exit(1)

    # Create reporter
    reporter = CowrieReporter(
        db_path=args.db,
        es_host=es_host,
        es_username=es_username,
        es_password=es_password,
        es_api_key=es_api_key,
        es_cloud_id=es_cloud_id,
        es_verify_ssl=verify_ssl,
        sensor_name=args.sensor,
        top_n=args.top_n,
        vt_recent_days=args.vt_recent_days,
    )

    try:
        if args.command == 'daily':
            if args.all_sensors:
                # Get all sensors from database
                cur = reporter.conn.cursor()
                cur.execute("SELECT DISTINCT hostname FROM sessions WHERE hostname IS NOT NULL")
                sensors = [row['hostname'] for row in cur.fetchall()]
                cur.close()

                # Generate reports for each sensor plus aggregate
                for s in sensors:
                    report = reporter.generate_daily_report(args.date, s)
                    reporter.index_report(report)
                # Aggregate
                report = reporter.generate_daily_report(args.date, None)
                reporter.index_report(report)
            else:
                # Single sensor or aggregate
                report = reporter.generate_daily_report(args.date, args.sensor)
                reporter.index_report(report)
                print(json.dumps(report, indent=2))

        elif args.command == 'backfill':
            reporter.backfill_daily(args.start, args.end, args.sensors)

        elif args.command == 'weekly':
            report = reporter.generate_weekly_rollup(args.week)
            if report:
                reporter.index_report(report, "cowrie.reports.weekly-write")
                print(json.dumps(report, indent=2))
            else:
                logger.error("Failed to generate weekly rollup")
        elif args.command == 'monthly':
            report = reporter.generate_monthly_rollup(args.month)
            if report:
                reporter.index_report(report, "cowrie.reports.monthly-write")
                print(json.dumps(report, indent=2))
            else:
                logger.error("Failed to generate monthly rollup")

        else:
            parser.print_help()

    finally:
        reporter.close()


if __name__ == "__main__":
    main()
