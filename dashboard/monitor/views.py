import json
import os
from django.shortcuts import render
from collections import Counter
from datetime import datetime

def home(request):
    alerts = []
    alerts_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "alerts.json")
    
    today_str = datetime.now().strftime("%Y-%m-%d")
    
    try:
        if os.path.exists(alerts_path):
            with open(alerts_path, "r") as f:
                for line in f:
                    if line.strip():
                        try:
                            alert = json.loads(line)
                            alerts.append(alert)
                        except json.JSONDecodeError:
                            continue
    except Exception:
        pass

    # Filtering for today
    today_alerts = [a for a in alerts if a['time'].startswith(today_str)]
    
    # Analytics
    total_alerts = len(alerts)
    today_count = len(today_alerts)
    
    # Attack Breakdown (All time)
    attack_types = [alert['type'] for alert in alerts]
    attack_breakdown = dict(Counter(attack_types))
    
    # Hourly breakdown for today's chart
    hourly_counts = [0] * 24
    for alert in today_alerts:
        try:
            hour = int(alert['time'].split(' ')[1].split(':')[0])
            hourly_counts[hour] += 1
        except (IndexError, ValueError):
            continue
            
    # Top Attacking IPs
    ip_counts = Counter([alert['ip'] for alert in alerts])
    top_ips = dict(ip_counts.most_common(5))
    
    # Unique IPs Today
    unique_ips_today = len(set([alert['ip'] for alert in today_alerts]))

    context = {
        "alerts": alerts[::-1][:15],  # Latest 15 alerts
        "total_alerts": total_alerts,
        "today_count": today_count,
        "attack_breakdown": attack_breakdown,
        "hourly_counts": hourly_counts,
        "top_ips": top_ips,
        "unique_ips_today": unique_ips_today,
        "today_date": today_str
    }

    return render(request, "index.html", context)

