import json
import os
from django.shortcuts import render
from collections import Counter

def home(request):
    alerts = []
    # Path relative to the dashboard directory where manage.py usually runs
    alerts_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "alerts.json")

    try:
        if os.path.exists(alerts_path):
            with open(alerts_path, "r") as f:
                for line in f:
                    if line.strip():
                        alerts.append(json.loads(line))
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # Reverse alerts to show newest first
    alerts.reverse()

    total_alerts = len(alerts)
    attack_types = [alert['type'] for alert in alerts]
    attack_breakdown = dict(Counter(attack_types))

    context = {
        "alerts": alerts[:20],  # Show last 20 alerts
        "total_alerts": total_alerts,
        "attack_breakdown": attack_breakdown
    }

    return render(request, "index.html", context)

