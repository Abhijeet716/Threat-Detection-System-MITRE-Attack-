import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta


def parse_arguments():
    parser = argparse.ArgumentParser(description='Python detection engine for threat logs')
    parser.add_argument('--logfile', required=True, help='Path to the event log file')
    return parser.parse_args()


def read_log_entries(path):
    try:
        with open(path, 'r', encoding='utf-8') as stream:
            return [line.strip() for line in stream if line.strip()]
    except FileNotFoundError:
        return []


def parse_event(line):
    try:
        event = json.loads(line)
        if 'time' in event:
            event['time'] = datetime.fromisoformat(event['time'].replace('Z', '+00:00'))
        return event
    except (ValueError, TypeError):
        return None


def summarize_by_ip(events):
    buckets = defaultdict(list)
    for event in events:
        if event and event.get('ip'):
            buckets[event['ip']].append(event)
    return buckets


def summarize_by_username(events):
    buckets = defaultdict(list)
    for event in events:
        if event.get('type') == 'login' and event.get('username'):
            buckets[event['username']].append(event)
    return buckets


def detect_brute_force(clusters, window_minutes=30, threshold=3):
    alerts = []
    cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
    for events in clusters.values():
        failures = [event for event in events if event.get('type') == 'login' and event.get('status') == 'failed' and event.get('time') >= cutoff]
        if len(failures) >= threshold:
            alerts.append({
                'type': 'Brute Force',
                'description': 'Multiple failed login attempts within a short window.',
                'mitre_id': 'T1110',
                'tactic': 'Credential Access',
                'ip': failures[0].get('ip', 'unknown'),
                'severity': 'critical'
            })
    return alerts


def detect_dos(events, interval_minutes=1, threshold=20):
    alerts = []
    cutoff = datetime.utcnow() - timedelta(minutes=interval_minutes)
    for ip, ip_events in events.items():
        recent_events = [event for event in ip_events if event.get('time') >= cutoff]
        if len(recent_events) >= threshold:
            alerts.append({
                'type': 'DoS / Traffic Spike',
                'description': 'High request volume detected from a single IP.',
                'mitre_id': 'T1499',
                'tactic': 'Impact',
                'ip': ip,
                'severity': 'high'
            })
    return alerts


def detect_sql_injection(events):
    alerts = []
    sql_patterns = ['union select', '1=1', '--', '/*', '*/', 'script', 'alert(']
    for ip, ip_events in events.items():
        for event in ip_events:
            if event.get('type') == 'request' and event.get('data'):
                data = event['data'].lower()
                if any(pattern in data for pattern in sql_patterns):
                    alerts.append({
                        'type': 'SQL Injection',
                        'description': 'Potential SQL injection attempt detected in request data.',
                        'mitre_id': 'T1190',
                        'tactic': 'Initial Access',
                        'ip': ip,
                        'severity': 'high'
                    })
                    break
    return alerts


def detect_xss(events):
    alerts = []
    xss_patterns = ['<script>', 'javascript:', 'onload=', 'onerror=']
    for ip, ip_events in events.items():
        for event in ip_events:
            if event.get('type') == 'request' and event.get('data'):
                data = event['data'].lower()
                if any(pattern in data for pattern in xss_patterns):
                    alerts.append({
                        'type': 'XSS Attempt',
                        'description': 'Potential cross-site scripting attempt detected.',
                        'mitre_id': 'T1189',
                        'tactic': 'Initial Access',
                        'ip': ip,
                        'severity': 'medium'
                    })
                    break
    return alerts


def detect_anomaly(events):
    alerts = []
    for ip, ip_events in events.items():
        if len(ip_events) > 100:  # Arbitrary threshold
            alerts.append({
                'type': 'Anomalous Activity',
                'description': 'Unusual volume of activity from IP.',
                'mitre_id': 'TA0005',
                'tactic': 'Defense Evasion',
                'ip': ip,
                'severity': 'low'
            })
    return alerts


def deduplicate_alerts(alerts):
    unique = []
    seen = set()
    for alert in alerts:
        key = (alert['type'], alert['ip'], alert['description'])
        if key not in seen:
            seen.add(key)
            unique.append(alert)
    return unique


def main():
    args = parse_arguments()
    lines = read_log_entries(args.logfile)
    events = [parse_event(line) for line in lines]
    ip_map = summarize_by_ip(events)
    user_map = summarize_by_username(events)

    alerts = []
    alerts.extend(detect_brute_force(ip_map))
    alerts.extend(detect_brute_force(user_map))
    alerts.extend(detect_dos(ip_map))
    alerts.extend(detect_suspicious_ips(ip_map))
    alerts.extend(detect_sql_injection(ip_map))
    alerts.extend(detect_xss(ip_map))
    alerts.extend(detect_anomaly(ip_map))
    print(json.dumps(deduplicate_alerts(alerts)))


if __name__ == '__main__':
    main()
