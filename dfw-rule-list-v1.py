import argparse
import requests
import json
import csv
import sys
import getpass
import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Configuration ---
HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# --- Helper Functions ---

def get_status_visual(disabled_state):
    """
    JSON 'disabled': false  -> UI Toggle ON (Green)
    JSON 'disabled': true   -> UI Toggle OFF (Red/Grey)
    """
    if disabled_state:
        return "🔴 Disabled"
    return "🟢 Enabled"

def clean_nsx_path(path_list):
    """
    Cleans lists like ["/infra/domains/default/groups/Web"] to "Web"
    """
    if not path_list:
        return "ANY"
    
    clean_names = []
    for item in path_list:
        if item == "ANY":
            clean_names.append("ANY")
        else:
            clean_names.append(item.split('/')[-1])
            
    return ", ".join(clean_names)

def get_dfw_policies(nsx_host, session):
    """Retrieves all Security Policies."""
    api_url = f"https://{nsx_host}/policy/api/v1/infra/domains/default/security-policies"
    try:
        response = session.get(api_url, headers=HEADERS, verify=False)
        response.raise_for_status()
        return response.json().get('results', [])
    except Exception as e:
        print(f"❌ Error fetching policies: {e}")
        return []

def get_policy_rules(nsx_host, policy_id, session):
    """Retrieves all rules inside a specific Policy."""
    api_url = f"https://{nsx_host}/policy/api/v1/infra/domains/default/security-policies/{policy_id}/rules"
    try:
        response = session.get(api_url, headers=HEADERS, verify=False)
        response.raise_for_status()
        return response.json().get('results', [])
    except Exception:
        return []

# --- Main Logic ---

def main():
    parser = argparse.ArgumentParser(description="NSX-T Firewall Rule Export")
    parser.add_argument('-s', '--server', required=True, help='NSX-T Manager IP')
    parser.add_argument('-u', '--username', required=True, help='NSX-T Username')
    parser.add_argument('-p', '--password', required=False, help='NSX-T Password')
    parser.add_argument('-o', '--output', required=False, help='Output CSV Filename')
    args = parser.parse_args()

    nsx_password = args.password or getpass.getpass(prompt=f'Password for {args.username}: ')
    
    session = requests.Session()
    session.auth = (args.username, nsx_password)

    print(f"🔄 Connecting to {args.server}...")
    policies = get_dfw_policies(args.server, session)
    
    if not policies:
        print("⚠️ No Policies found.")
        return

    export_data = []

    for policy in policies:
        policy_name = policy.get('display_name')
        policy_id = policy.get('id')
        
        # Skip Layer 2 Policies
        if 'LAYER2' in policy.get('section_type', ''):
            continue

        rules = get_policy_rules(args.server, policy_id, session)
        
        # Add Policy Header
        export_data.append({"type": "POLICY_HEADER", "name": policy_name, "count": len(rules)})

        for rule in rules:
            # --- Field Mapping based on your JSON ---
            r_name = rule.get('display_name', 'N/A')
            r_id = rule.get('id', 'N/A') # Matches "default-layer3-rule"
            
            sources = clean_nsx_path(rule.get('source_groups', []))
            destinations = clean_nsx_path(rule.get('destination_groups', []))
            services = clean_nsx_path(rule.get('services', []))
            
            # UPDATED: Changed from 'context_profiles' to 'profiles' based on your JSON
            profiles = clean_nsx_path(rule.get('profiles', [])) 
            
            applied_to = clean_nsx_path(rule.get('scope', []))
            action = rule.get('action', 'ALLOW')
            
            # Status Logic
            is_disabled = rule.get('disabled', False) # JSON "disabled": false
            status_visual = get_status_visual(is_disabled)

            export_data.append({
                "type": "RULE",
                "Policy": policy_name,
                "Name": r_name,
                "ID": r_id,
                "Sources": sources,
                "Destinations": destinations,
                "Services": services,
                "Context Profiles": profiles,
                "Applied To": applied_to,
                "Action": action,
                "Status": status_visual,
                "Raw_Status": "DISABLED" if is_disabled else "ENABLED"
            })

    # --- Console Output ---
    print("\n" + "="*145)
    print(f"{'Name':<30} {'ID':<20} {'Sources':<15} {'Destinations':<15} {'Services':<10} {'Profiles':<10} {'Applied To':<15} {'Action':<8} {'Status':<10}")
    print("="*145)

    for item in export_data:
        if item["type"] == "POLICY_HEADER":
            print(f"\n📂 POLICY: {item['name']} ({item['count']} Rules)")
            print("-" * 145)
        else:
            print(f"{item['Name'][:29]:<30} {item['ID'][:19]:<20} {item['Sources'][:14]:<15} {item['Destinations'][:14]:<15} {item['Services'][:9]:<10} {item['Context Profiles'][:9]:<10} {item['Applied To'][:14]:<15} {item['Action']:<8} {item['Status']:<10}")

    # --- CSV Export ---
    if args.output:
        try:
            with open(args.output, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Policy Name', 'Rule Name', 'ID', 'Sources', 'Destinations', 'Services', 'Context Profiles', 'Applied To', 'Action', 'State'])
                for item in export_data:
                    if item["type"] == "RULE":
                        writer.writerow([
                            item['Policy'], item['Name'], item['ID'], item['Sources'], 
                            item['Destinations'], item['Services'], item['Context Profiles'], 
                            item['Applied To'], item['Action'], item['Raw_Status']
                        ])
            print(f"\n✅ Exported to CSV: {args.output}")
        except Exception as e:
            print(f"❌ CSV Error: {e}")

if __name__ == "__main__":
    main()
