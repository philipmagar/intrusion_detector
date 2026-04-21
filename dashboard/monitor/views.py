from django.shortcuts import render

# Create your views here.
import json
from django.shortcuts import render

def home(request):
    alerts = []

    try:
        with open("../../../alerts.json", "r") as f:
            for line in f:
                alerts.append(json.loads(line))
    except FileNotFoundError:
        pass

    return render(request, "index.html", {"alerts": alerts})
