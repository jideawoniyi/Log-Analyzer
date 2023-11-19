## Log Analysis Script

This script analyzes a log file, detecting suspicious activity based on specific patterns of failed and successful logins from the same IP address.

### Script Code

```python
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
```

## Usage

Place the log file in the same directory as the script, naming it fake_log.txt.
Run the script using a Python interpreter.

## Output

The script will output an alert if it detects 10 consecutive failed login attempts followed by a successful login from the same IP address.
