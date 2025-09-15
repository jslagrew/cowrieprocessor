# Cowrie Elasticsearch Reporting - Quick Implementation Guide

## Setup Steps

### 1. Install Dependencies
```bash
pip install elasticsearch>=8.0.0
```

### 2. Copy Files
- Save `es_reports.py` to your dshield directory
- Save index templates under `scripts/` (daily/weekly/monthly JSON files)

### 3. Create Index Templates & ILM Policies (no delete)
```bash
# ILM: Daily hot 7d -> cold (no delete)
curl -X PUT "localhost:9200/_ilm/policy/cowrie.reports.daily" -H "Content-Type: application/json" \
  -d '{"policy":{"phases":{"hot":{"min_age":"0ms","actions":{"set_priority":{"priority":100}}},"cold":{"min_age":"7d","actions":{"set_priority":{"priority":0}}}}}}'

# ILM: Weekly hot 30d -> cold (no delete)
curl -X PUT "localhost:9200/_ilm/policy/cowrie.reports.weekly" -H "Content-Type: application/json" \
  -d '{"policy":{"phases":{"hot":{"min_age":"0ms","actions":{"set_priority":{"priority":100}}},"cold":{"min_age":"30d","actions":{"set_priority":{"priority":0}}}}}}'

# ILM: Monthly hot 90d -> cold (no delete)
curl -X PUT "localhost:9200/_ilm/policy/cowrie.reports.monthly" -H "Content-Type: application/json" \
  -d '{"policy":{"phases":{"hot":{"min_age":"0ms","actions":{"set_priority":{"priority":100}}},"cold":{"min_age":"90d","actions":{"set_priority":{"priority":0}}}}}}'

# Index templates per type
curl -X PUT "localhost:9200/_index_template/cowrie.reports.daily" -H "Content-Type: application/json" \
  -d @scripts/cowrie.reports.daily-index.json
curl -X PUT "localhost:9200/_index_template/cowrie.reports.weekly" -H "Content-Type: application/json" \
  -d @scripts/cowrie.reports.weekly-index.json
curl -X PUT "localhost:9200/_index_template/cowrie.reports.monthly" -H "Content-Type: application/json" \
  -d @scripts/cowrie.reports.monthly-index.json
```

### 4. Set Environment Variables
```bash
export ES_HOST=localhost:9200
export ES_USERNAME=elastic
export ES_PASSWORD=your_password
```

### 5. Test Report Generation
```bash
# Test today's report
python3 es_reports.py daily --all-sensors

# Backfill last week
python3 es_reports.py backfill --start 2024-12-14 --end 2024-12-20
```

### 6. Schedule with Cron
```bash
crontab -e
# Add:
30 4 * * * cd /home/cowrie/dshield && python3 es_reports.py daily --all-sensors
0 5 * * 1 python3 es_reports.py weekly
30 5 1 * * python3 es_reports.py monthly
```

## Key Features Implemented

### Daily Reports (Per-sensor + Aggregate)
- **Session Metrics**: Total, unique IPs, usernames, passwords, protocols
- **Command Statistics**: Total, unique, top commands
- **File Activity**: Downloads, uploads, VT classifications
- **Enrichments**: URLhaus tags, ASN, country, SPUR data
- **Abnormality Detection**: Uncommon command counts, recent VT submissions
- **Alerts**: IP spikes, new VT classifications, high tunnel usage

### Alert Thresholds
- **IP Spike**: >50% increase from 7-day average
- **New VT Classification**: Not seen in past 30 days
- **High Tunnel Usage**: >30% of sessions

### Multi-Sensor Support
- Individual reports per sensor (honeypot1, honeypot2)
- Aggregate report combining all sensors
- Sensor name from hostname or override with `--sensor`

### Data Structure
```
cowrie.reports.daily-*
  └── sensor:date_utc (e.g., "honeypot1:2024-12-20")
      ├── sessions (metrics)
      ├── commands (statistics)
      ├── files (activity)
      ├── enrichments (3rd party data)
      ├── abnormalities (detection flags)
      └── alerts (threshold triggers)

cowrie.reports.weekly-*
  └── aggregate:YYYY-Www (e.g., "aggregate:2024-W51")
      └── Aggregated daily metrics

cowrie.reports.monthly-*
  └── aggregate:YYYY-MM (e.g., "aggregate:2024-12")
      ├── Aggregated daily metrics
      └── trends (month-over-month changes)
```

## Usage Examples

### Daily Operations
```bash
# Generate all reports for today
python3 es_reports.py daily --all-sensors

# Generate for specific date
python3 es_reports.py daily --date 2024-12-19 --all-sensors

# Single sensor only
python3 es_reports.py daily --sensor honeypot1
```

### Backfilling
```bash
# Backfill date range
python3 es_reports.py backfill --start 2024-11-01 --end 2024-11-30

# Backfill specific sensors
python3 es_reports.py backfill --start 2024-12-01 --end 2024-12-20 --sensors honeypot1 honeypot2
```

### Rollups
```bash
# Weekly rollup (current week)
python3 es_reports.py weekly

# Specific week
python3 es_reports.py weekly --week 2024-W50

# Monthly rollup
python3 es_reports.py monthly --month 2024-11
```

## Kibana Queries

### View Latest Daily Report
```
GET cowrie.reports.daily-*/_search
{
  "size": 1,
  "sort": [{"date_utc": "desc"}],
  "query": {"term": {"sensor": "aggregate"}}
}
```

### Find High Severity Alerts
```
GET cowrie.reports.daily-*/_search
{
  "query": {
    "nested": {
      "path": "alerts",
      "query": {"term": {"alerts.severity": "high"}}
    }
  }
}
```

### Session Trend (Last 30 Days)
```
GET cowrie.reports.daily-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        {"term": {"sensor": "aggregate"}},
        {"range": {"date_utc": {"gte": "now-30d"}}}
      ]
    }
  },
  "aggs": {
    "daily_sessions": {
      "date_histogram": {
        "field": "date_utc",
        "calendar_interval": "day"
      },
      "aggs": {
        "sessions": {"sum": {"field": "sessions.total"}}
      }
    }
  }
}
```

## Monitoring

### Check Report Generation
```bash
# View last 5 reports
curl -s "localhost:9200/cowrie.reports.daily-*/_search?size=5&sort=@timestamp:desc" | jq '.hits.hits[]._source | {date: .date_utc, sensor: .sensor, sessions: .sessions.total}'

# Check for missing days
python3 -c "
from datetime import datetime, timedelta
import requests
for i in range(7):
    date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
    r = requests.get(f'http://localhost:9200/cowrie.reports.daily-*/_count?q=date_utc:{date}')
    print(f'{date}: {r.json()[\"count\"]} reports')
"
```

### View Alerts
```bash
# Today's alerts
curl -s "localhost:9200/cowrie.reports.daily-*/_search?q=date_utc:$(date +%Y-%m-%d)" | \
  jq '.hits.hits[]._source | select(.alerts | length > 0) | {sensor, alerts}'
```

## Troubleshooting

### Common Issues

1. **No data in reports**
   - Check SQLite has data: `sqlite3 cowrieprocessor.sqlite "SELECT COUNT(*) FROM sessions"`
   - Verify date range has sessions

2. **Connection errors**
   - Test ES connection: `curl localhost:9200`
   - Check credentials in environment

3. **Missing enrichments**
   - Enrichments show as null if not available
   - Check if SPUR/URLhaus data exists in SQLite

4. **Slow queries**
   - Add index on timestamp: `CREATE INDEX idx_sessions_timestamp ON sessions(timestamp)`
   - Limit date ranges for backfill

### Debug Mode
```bash
# Enable debug logging
python3 -c "import logging; logging.basicConfig(level=logging.DEBUG)" es_reports.py daily --date 2024-12-20
```

## Next Steps

1. **Create Kibana Dashboard**
   - Import visualizations for trends
   - Set up alert watchers
   
2. **Tune Alert Thresholds**
   - Adjust percentages based on your environment
   - Add custom alerts for specific threats

3. **Extend Metrics**
   - Add GeoIP aggregations
   - Include command sequence analysis
   - Track persistence indicators

4. **Integration**
   - Forward high-severity alerts to SIEM
   - Create Slack/email notifications
   - Build executive reports from monthly rollups
