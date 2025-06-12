#!/usr/bin/env python3

import requests
import time
import os

# Constants
URL = "https://ips.voxility.com/get_attacks.php"
EXPORT_PATH = "/tmp/node_exporter/voxility_attacks.prom"  # Path for textfile collector
METRIC_NAME = "voxility_attack_ip"  # Base metric name

def fetch_data():
    try:
        response = requests.get(URL)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching data: {e}")
        return []

def write_prometheus_file(data):
    try:
        lines = [
            f"# HELP {METRIC_NAME} Active IPs under attack from Voxility",
            f"# TYPE {METRIC_NAME} gauge"
        ]

        timestamp = int(time.time())
        for entry in data:
            ip = entry.get("ip", "unknown")
            attack_type = entry.get("type", "unknown").replace(" ", "_")

            line = (
                f'{METRIC_NAME}{{ip="{ip}",attack_type="{attack_type}"}} 1 {timestamp}'
            )
            lines.append(line)

        with open(EXPORT_PATH, "w") as f:
            f.write("\n".join(lines) + "\n")

        #print(f"Metrics written to {EXPORT_PATH}")
    except Exception as e:
        print(f"Error writing Prometheus file: {e}")

def main():
    data = fetch_data()
    #print(data["attacks"])
    try:
        if isinstance(data["attacks"], list) and data:
            write_prometheus_file(data["attacks"])
    except Exception as e:
        data = []
        write_prometheus_file(data)
        #print("No valid data received.")

if __name__ == "__main__":
    main()
