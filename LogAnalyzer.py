import re
from collections import defaultdict

# Regex pattern to extract key details from log entries
pattern = r'EventID: (\\d+), Account: (.*?), SourceIP: (.*?), Status: (\\w+)'

# Read the log file and parse using the regex pattern
with open('fake_log.txt', 'r') as file:
    logs = file.readlines()
parsed_logs = [re.match(pattern, log).groups() if re.match(pattern, log) else None for log in logs]

# Organize logs by IP address for easier analysis
ip_activity = defaultdict(list)
for log in parsed_logs:
    if log:
        event_id, _, ip, status = log
        ip_activity[ip].append((event_id, status))

# Detect suspicious activity: 10 failed logins followed by a success from the same IP
for ip, activities in ip_activity.items():
    for i in range(len(activities) - 10):
        if all(act[1] == "Failure" for act in activities[i:i+10]) and activities[i+10][1] == "Success":
            print(f"Suspicious activity detected from IP {ip}!")
            break
