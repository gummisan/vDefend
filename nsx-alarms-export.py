import requests
import urllib3
import csv
import getpass
import argparse
from datetime import datetime

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Set up Standardized Command Line Arguments ---
parser = argparse.ArgumentParser(description="Export NSX Alarms to CSV and Terminal")
parser.add_argument("-s", "--server", help="NSX Manager IP/FQDN")
parser.add_argument("-u", "--username", help="NSX Username")
parser.add_argument("-p", "--password", help="NSX Password (optional)")
parser.add_argument("-o", "--output", help="Output CSV filename (e.g. stats.csv)", default="nsx_all_alarms.csv")
args = parser.parse_args()

# --- Determine Credentials (Arguments vs Prompts) ---
print("\n=== NSX Manager Authentication ===")

# If an argument was provided, use it. Otherwise, prompt the user.
nsx_mgr = args.server if args.server else input("Enter NSX Manager IP/FQDN: ").strip()
username = args.username if args.username else (input("Enter NSX Username [admin]: ").strip() or "admin")
password = args.password if args.password else getpass.getpass("Enter NSX Password: ")
csv_file = args.output

print("==================================\n")
# ---------------------------------------------------

url = f"https://{nsx_mgr}/api/v1/alarms"
headers = {'Content-Type': 'application/json'}

entity_cache = {}

def get_friendly_name(entity_id):
    if not entity_id:
        return "N/A"
    if entity_id in entity_cache:
        return entity_cache[entity_id]
        
    search_url = f"https://{nsx_mgr}/api/v1/search/query?query=id:{entity_id}"
    try:
        res = requests.get(search_url, auth=(username, password), headers=headers, verify=False)
        if res.status_code == 200:
            results = res.json().get('results', [])
            if results:
                display_name = results[0].get('display_name', entity_id)
                entity_cache[entity_id] = display_name
                return display_name
    except Exception:
        pass 
        
    entity_cache[entity_id] = entity_id
    return entity_id

print(f"Connecting to NSX Manager at {nsx_mgr}...")
response = requests.get(url, auth=(username, password), headers=headers, verify=False)

if response.status_code == 200:
    alarms = response.json().get('results', [])
    print(f"Found {len(alarms)} total alarms. Resolving names...\n")
    
    # Print Terminal Header
    print(f"{'Entity Name':<25} | {'Event Type':<35} | {'Severity':<10} | {'Status':<8} | {'Time':<20} | {'Description'}")
    print("-" * 140)
    
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Feature', 'Event Type', 'Entity Name', 'Severity', 'Last Reported Time', 'Status', 'Description'])
        
        for alarm in alarms:
            timestamp_ms = alarm.get('last_reported_time')
            if timestamp_ms:
                reported_time = datetime.fromtimestamp(timestamp_ms / 1000.0).strftime('%Y-%m-%d %H:%M:%S')
            else:
                reported_time = "N/A"

            entity_name = alarm.get('node_display_name') or alarm.get('display_name')
            if not entity_name:
                entity_name = get_friendly_name(alarm.get('entity_id'))

            event_type = alarm.get('event_type', 'N/A')
            severity = alarm.get('severity', 'N/A')
            status = alarm.get('status', 'N/A')
            
            description = alarm.get('description', alarm.get('message', 'N/A'))

            # 1. Print to Terminal
            print(f"{entity_name[:23]:<25} | {event_type[:33]:<35} | {severity:<10} | {status[:8]:<8} | {reported_time:<20} | {description[:35]}...")

            # 2. Write to CSV
            writer.writerow([
                alarm.get('feature_name', 'N/A'),
                event_type,
                entity_name,
                severity,
                reported_time,
                status,
                description
            ])
            
    print(f"\nSuccess! Data successfully exported to {csv_file}\n")
elif response.status_code in [401, 403]:
    print("\nAuthentication Failed! Please check your username and password.")
else:
    print(f"\nError fetching alarms: HTTP {response.status_code}")
    print(response.text)
