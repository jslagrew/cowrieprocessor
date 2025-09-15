# Deployment Configuration for Cowrie Reports

## 1. Elasticsearch ILM Policies (no delete)

Create three policies that never delete, only age to cold:

```json
PUT _ilm/policy/cowrie.reports.daily
{
  "policy": {
    "phases": {
      "hot": {"min_age": "0ms", "actions": {"set_priority": {"priority": 100}}},
      "cold": {"min_age": "7d", "actions": {"set_priority": {"priority": 0}}}
    }
  }
}

PUT _ilm/policy/cowrie.reports.weekly
{
  "policy": {
    "phases": {
      "hot": {"min_age": "0ms", "actions": {"set_priority": {"priority": 100}}},
      "cold": {"min_age": "30d", "actions": {"set_priority": {"priority": 0}}}
    }
  }
}

PUT _ilm/policy/cowrie.reports.monthly
{
  "policy": {
    "phases": {
      "hot": {"min_age": "0ms", "actions": {"set_priority": {"priority": 100}}},
      "cold": {"min_age": "90d", "actions": {"set_priority": {"priority": 0}}}
    }
  }
}
```

## 2. Bootstrap Indices

```bash
# Create index templates (daily/weekly/monthly)
curl -X PUT "localhost:9200/_index_template/cowrie.reports.daily" \
  -H "Content-Type: application/json" \
  -d @scripts/cowrie.reports.daily-index.json

curl -X PUT "localhost:9200/_index_template/cowrie.reports.weekly" \
  -H "Content-Type: application/json" \
  -d @scripts/cowrie.reports.weekly-index.json

curl -X PUT "localhost:9200/_index_template/cowrie.reports.monthly" \
  -H "Content-Type: application/json" \
  -d @scripts/cowrie.reports.monthly-index.json

# Create initial indices with write aliases
curl -X PUT "localhost:9200/cowrie.reports.daily-000001" \
  -H "Content-Type: application/json" \
  -d '{
    "aliases": {
      "cowrie.reports.daily-write": {}
    }
  }'

curl -X PUT "localhost:9200/cowrie.reports.weekly-000001" \
  -H "Content-Type: application/json" \
  -d '{
    "aliases": {
      "cowrie.reports.weekly-write": {}
    }
  }'

curl -X PUT "localhost:9200/cowrie.reports.monthly-000001" \
  -H "Content-Type: application/json" \
  -d '{
    "aliases": {
      "cowrie.reports.monthly-write": {}
    }
  }'
```

## 3. Systemd Timer Configuration

### `/etc/systemd/system/cowrie-reports-daily.service`

```ini
[Unit]
Description=Generate Cowrie Daily Reports for Elasticsearch
After=network.target elasticsearch.service

[Service]
Type=oneshot
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/dshield
Environment="ES_HOST=localhost:9200"
Environment="ES_USERNAME=elastic"
Environment="ES_PASSWORD=changeme"
ExecStart=/usr/bin/python3 /home/cowrie/dshield/es_reports.py daily --all-sensors
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### `/etc/systemd/system/cowrie-reports-daily.timer`

```ini
[Unit]
Description=Run Cowrie Daily Reports at 04:30 UTC
Requires=cowrie-reports-daily.service

[Timer]
OnCalendar=04:30
Persistent=true

[Install]
WantedBy=timers.target
```

### `/etc/systemd/system/cowrie-reports-weekly.service`

```ini
[Unit]
Description=Generate Cowrie Weekly Reports for Elasticsearch
After=network.target elasticsearch.service

[Service]
Type=oneshot
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/dshield
Environment="ES_HOST=localhost:9200"
Environment="ES_USERNAME=elastic"
Environment="ES_PASSWORD=changeme"
ExecStart=/usr/bin/python3 /home/cowrie/dshield/es_reports.py weekly
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### `/etc/systemd/system/cowrie-reports-weekly.timer`

```ini
[Unit]
Description=Run Cowrie Weekly Reports on Mondays at 05:00 UTC
Requires=cowrie-reports-weekly.service

[Timer]
OnCalendar=Mon *-*-* 05:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

### Enable the timers:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cowrie-reports-daily.timer
sudo systemctl enable cowrie-reports-weekly.timer
sudo systemctl start cowrie-reports-daily.timer
sudo systemctl start cowrie-reports-weekly.timer

# Check timer status
sudo systemctl list-timers | grep cowrie
```

## 4. Alternative: Cron Configuration

If you prefer cron over systemd:

```bash
# Edit crontab for cowrie user
crontab -e

# Add these lines:
# Daily reports at 04:30 UTC
30 4 * * * cd /home/cowrie/dshield && python3 es_reports.py daily --all-sensors >> /var/log/cowrie-reports.log 2>&1

# Weekly reports on Mondays at 05:00 UTC
0 5 * * 1 cd /home/cowrie/dshield && python3 es_reports.py weekly >> /var/log/cowrie-reports.log 2>&1

# Monthly reports on 1st of month at 05:30 UTC
30 5 1 * * cd /home/cowrie/dshield && python3 es_reports.py monthly >> /var/log/cowrie-reports.log 2>&1
```

## 5. Environment Variables Configuration

Create `/home/cowrie/dshield/.env`:

```bash
# Elasticsearch Configuration
ES_HOST=localhost:9200
ES_USERNAME=elastic
ES_PASSWORD=your_secure_password
# Or use API key instead:
# ES_API_KEY=your_api_key_here

# Or for Elastic Cloud:
# ES_CLOUD_ID=your_cloud_id
# ES_API_KEY=your_cloud_api_key

# Optional: Disable SSL verification for self-signed certs
# ES_VERIFY_SSL=false

# Report Configuration
TOP_N=10
VT_RECENT_DAYS=5
```

## 6. Testing Commands

```bash
# Test daily report generation (dry run - just prints)
python3 es_reports.py daily --date 2024-12-20

# Generate report for specific sensor
python3 es_reports.py daily --sensor honeypot1 --date 2024-12-20

# Backfill last 7 days
python3 es_reports.py backfill --start 2024-12-14 --end 2024-12-20

# Generate weekly rollup
python3 es_reports.py weekly --week 2024-W51

# Check if reports are being indexed
curl -X GET "localhost:9200/cowrie.reports.daily-*/_search?size=1&pretty"
```

## 7. Kibana Dashboard Queries

Example queries for visualizations:

### Daily Session Trend
```json
{
  "query": {
    "bool": {
      "filter": [
        {"term": {"report_type": "daily"}},
        {"term": {"sensor": "aggregate"}},
        {"range": {"date_utc": {"gte": "now-30d"}}}
      ]
    }
  },
  "aggs": {
    "sessions_over_time": {
      "date_histogram": {
        "field": "date_utc",
        "calendar_interval": "day"
      },
      "aggs": {
        "total_sessions": {
          "sum": {"field": "sessions.total"}
        }
      }
    }
  }
}
```

### Alert Monitor
```json
{
  "query": {
    "bool": {
      "filter": [
        {"nested": {
          "path": "alerts",
          "query": {
            "term": {"alerts.severity": "high"}
          }
        }},
        {"range": {"date_utc": {"gte": "now-7d"}}}
      ]
    }
  }
}
```

## 8. Monitoring & Alerting

### Watcher Alert for High Severity Alerts
```json
PUT _watcher/watch/cowrie_high_severity_alert
{
  "trigger": {
    "schedule": {"interval": "5m"}
  },
  "input": {
    "search": {
      "request": {
        "indices": ["cowrie.reports.daily-*"],
        "body": {
          "query": {
            "bool": {
              "filter": [
                {"range": {"@timestamp": {"gte": "now-5m"}}},
                {"nested": {
                  "path": "alerts",
                  "query": {
                    "term": {"alerts.severity": "high"}
                  }
                }}
              ]
            }
          }
        }
      }
    }
  },
  "condition": {
    "compare": {"ctx.payload.hits.total": {"gt": 0}}
  },
  "actions": {
    "send_email": {
      "email": {
        "to": "security@example.com",
        "subject": "Cowrie High Severity Alert",
        "body": "New high severity alerts detected in Cowrie reports"
      }
    }
  }
}
```

## 9. Requirements Update

Add to `requirements.txt`:
```
elasticsearch>=8.0.0,<9.0.0
```

## 10. Backup Strategy

```bash
# Daily backup of SQLite database (add to cron)
0 3 * * * sqlite3 /home/cowrie/cowrieprocessor.sqlite ".backup /backup/cowrie/cowrieprocessor-$(date +\%Y\%m\%d).sqlite"

# Elasticsearch snapshot repository setup
PUT _snapshot/cowrie_backup
{
  "type": "fs",
  "settings": {
    "location": "/backup/elasticsearch/cowrie"
  }
}

# Create snapshot policy
PUT _slm/policy/cowrie-reports-backup
{
  "schedule": "0 0 2 * * ?",
  "name": "<cowrie-reports-{now/d}>",
  "repository": "cowrie_backup",
  "config": {
    "indices": ["cowrie.reports.*"],
    "include_global_state": false
  },
  "retention": {
    "expire_after": "30d",
    "min_count": 7,
    "max_count": 30
  }
}
```
