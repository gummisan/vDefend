import argparse
import requests
import json
import csv
import sys
import getpass
import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress warnings for insecure requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Configuration ---
HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# --- Helper Functions ---

def convert_epoch_to_date(epoch_ms):
    """Converts Epoch milliseconds to a readable string (YYYY-MM-DD HH:MM:SS)."""
    try:
        if not epoch_ms:
            return "N/A"
        seconds = int(epoch_ms) / 1000.0
        dt_obj = datetime.datetime.fromtimestamp(seconds)
        return dt_obj.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "Invalid Date"

def get_dfw_sections(nsx_host, session):
    """Retrieves all Distributed Firewall Security Policies with AUTH CHECK."""
    policies_api = "/policy/api/v1/infra/domains/default/security-policies"
    url = f"https://{nsx_host}{policies_api}"
    
    print(f"Connecting to NSX-T Manager at {nsx_host}...")
    
    try:
        response = session.get(url, headers=HEADERS, verify=False)
        response.raise_for_status() 
        return response.json().get('results', [])

    # --- SPECIFIC ERROR HANDLING ---
    except requests.exceptions.HTTPError as err:
        if response.status_code in [401, 403]:
            print("\n❌ AUTHENTICATION FAILED!")
            print("   Please check your Username and Password.")
            print(f"   Server responded with: {response.status_code} {response.reason}")
        elif response.status_code == 404:
            print("\n❌ API ENDPOINT NOT FOUND!")
            print("   The NSX-T version might be too old or the URL is incorrect.")
        else:
            print(f"\n❌ HTTP Error: {err}")
        return None

    except requests.exceptions.ConnectionError:
        print("\n❌ CONNECTION FAILED!")
        print(f"   Could not reach {nsx_host}. Check the IP address and VPN/Network connection.")
        return None

    except Exception as err:
        print(f"\n❌ Unexpected Error: {err}")
        return None

def get_policy_rules(nsx_host, policy_id, session):
    """Retrieves all rules for a given Security Policy ID."""
    rules_api = f"/policy/api/v1/infra/domains/default/security-policies/{policy_id}/rules"
    url = f"https://{nsx_host}{rules_api}"
    
    try:
        response = session.get(url, headers=HEADERS, verify=False)
        response.raise_for_status() 
        return response.json().get('results', [])
    except Exception:
        return []

def get_rule_statistics(nsx_host, policy_id, rule_id, session):
    """Retrieves statistics matching the user's specific JSON structure."""
    stats_api = f"/policy/api/v1/infra/domains/default/security-policies/{policy_id}/rules/{rule_id}/statistics"
    url = f"https://{nsx_host}{stats_api}"
    
    try:
        response = session.get(url, headers=HEADERS, verify=False)
        response.raise_for_status() 
        stats_data = response.json()
        
        if stats_data.get('results'):
            first_result = stats_data['results'][0]
            stats = first_result.get('statistics') or first_result.get('rule_statistics') or {}
            return stats
            
        return None
            
    except Exception:
        return None

# --- Main Logic ---

def main():
    parser = argparse.ArgumentParser(description="Retrieve NSX-T DFW Rule Statistics (Grouped).")
    parser.add_argument('-s', '--server', required=True, help='NSX-T Manager IP/FQDN')
    parser.add_argument('-u', '--username', required=True, help='NSX-T Username')
    parser.add_argument('-p', '--password', required=False, help='NSX-T Password (optional)')
    parser.add_argument('-o', '--output', required=False, help='Output CSV filename (e.g. stats.csv)')
    args = parser.parse_args()

    # Secure Password Logic
    nsx_password = args.password
    if not nsx_password:
        nsx_password = getpass.getpass(prompt=f'Enter password for {args.username}@{args.server}: ')

    nsx_session = requests.Session()
    nsx_session.auth = (args.username, nsx_password)

    # 1. Get Policies (With Login Check)
    all_policies = get_dfw_sections(args.server, nsx_session)

    # If None is returned, it means a specific error was printed inside the function
    if all_policies is None:
        return # Stop script immediately
    
    if not all_policies:
        print("⚠️ Login successful, but no Security Policies were found.")
        return

    print(f"✅ Login Successful! Processing {len(all_policies)} Security Policies...")
    all_stats_data = []

    # 2. Iterate to Collect Data
    for policy in all_policies:
        policy_id = policy.get('id')
        policy_display_name = policy.get('display_name', 'N/A')
        section_type = policy.get('section_type', 'N/A')

        # Skip Layer 2 Policies
        if 'LAYER2' in section_type:
            continue

        print(f"-> Scanning Policy: {policy_display_name}")

        rules_in_policy = get_policy_rules(args.server, policy_id, nsx_session)
        
        if not rules_in_policy:
            continue

        for rule in rules_in_policy:
            try:
                rule_uuid = rule.get('id')
                rule_display_name = rule.get('display_name', 'N/A')
                
                # Audit Info
                raw_mod_time = rule.get('_last_modified_time')
                last_user = rule.get('_last_modified_user', 'N/A')
                readable_time = convert_epoch_to_date(raw_mod_time)

                # Stats
                rule_stats = get_rule_statistics(args.server, policy_id, rule_uuid, nsx_session)
                
                if rule_stats is not None:
                    hit_count = rule_stats.get('hit_count', 0)
                    packet_count = rule_stats.get('packet_count', 0)
                    session_count = rule_stats.get('session_count', 0)
                    byte_count = rule_stats.get('byte_count', 0)
                    numeric_id = rule_stats.get('internal_rule_id', 'N/A')
                    
                    mb_count = round(byte_count / (1024 * 1024), 2)
                    
                    all_stats_data.append({
                        "Policy": policy_display_name,
                        "Rule Name": rule_display_name,
                        "Rule ID": numeric_id,
                        "Hit Count": hit_count,
                        "Packet Count": packet_count,
                        "Session Count": session_count,
                        "Bytes (MB)": mb_count,
                        "Last Modified": readable_time,
                        "Modified By": last_user
                    })

            except Exception:
                continue

    # 3. Output Results to Console (Grouped by Policy)
    print("\n")
    if not all_stats_data:
        print("⚠️ No statistics data collected.")
    else:
        # Loop through data to print Grouped Output
        current_policy = None
        
        w_rule = 35
        w_id = 10
        w_hit = 15
        w_bytes = 12
        w_time = 22
        w_user = 15
        
        header_format = f"{{:<{w_rule}}} {{:<{w_id}}} {{:<{w_hit}}} {{:<{w_bytes}}} {{:<{w_time}}} {{:<{w_user}}}"
        row_format    = f"{{:<{w_rule}}} {{:<{w_id}}} {{:<{w_hit}}} {{:<{w_bytes}}} {{:<{w_time}}} {{:<{w_user}}}"
        divider       = "-" * (w_rule + w_id + w_hit + w_bytes + w_time + w_user)

        for row in all_stats_data:
            if row['Policy'] != current_policy:
                current_policy = row['Policy']
                print("\n" + "=" * 80)
                print(f"📘 POLICY: {current_policy}")
                print("=" * 80)
                print(header_format.format("Rule Name", "Rule ID", "Hit Count", "Bytes (MB)", "Last Modified", "Modified By"))
                print(divider)
            
            print(row_format.format(
                row['Rule Name'][:w_rule-1], 
                str(row['Rule ID'])[:w_id-1], 
                f"{row['Hit Count']:,}", 
                f"{row['Bytes (MB)']:,}", 
                row['Last Modified'], 
                row['Modified By'][:w_user-1]
            ))

    # 4. CSV Export
    if args.output and all_stats_data:
        try:
            with open(args.output, mode='w', newline='', encoding='utf-8') as csv_file:
                fieldnames = ["Policy", "Rule Name", "Rule ID", "Hit Count", "Packet Count", "Session Count", "Bytes (MB)", "Last Modified", "Modified By"]
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

                writer.writeheader()
                for row in all_stats_data:
                    writer.writerow(row)
            
            print(f"\n✅ Successfully exported data to: {args.output}")
        except Exception as e:
            print(f"\n❌ Failed to write CSV file: {e}")

if __name__ == "__main__":
    main()
