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

def get_group_ip_map(nsx_host, session):
    """
    Fetches ALL groups and builds a dictionary:
    { '/infra/domains/default/groups/MyGroup': '192.168.1.10, 10.0.0.0/24' }
    Only resolves STATIC IPs. Dynamic logic (Tags/VM names) is skipped for performance.
    """
    print("   ... Caching Group Definitions (This may take a moment) ...")
    api_url = f"https://{nsx_host}/policy/api/v1/infra/domains/default/groups"
    group_map = {}
    
    try:
        # Loop to handle pagination if > 1000 groups
        cursor = None
        while True:
            params = {'cursor': cursor} if cursor else {}
            response = session.get(api_url, headers=HEADERS, verify=False, params=params)
            response.raise_for_status()
            data = response.json()
            
            for group in data.get('results', []):
                group_path = group.get('path')
                ip_list = []
                
                # Check expressions for IPAddressExpression
                for expr in group.get('expression', []):
                    # Check if it's a simple IP Expression
                    if expr.get('resource_type') == 'IPAddressExpression':
                        ip_list.extend(expr.get('ip_addresses', []))
                    
                    # Also check Conjunctions (OR/AND logic) containing IPs
                    elif expr.get('resource_type') == 'ConjunctionOperator':
                         # If nested expressions exist (simplified check)
                         pass 

                # If we found IPs, store them. Otherwise, leave empty (will default to Name later)
                if ip_list:
                    group_map[group_path] = ", ".join(ip_list)
            
            cursor = data.get('cursor')
            if not cursor:
                break
                
        print(f"   ✅ Cached {len(group_map)} Groups with Static IPs.")
        return group_map

    except Exception as e:
        print(f"⚠️ Warning: Could not fetch groups. Output will show Group Names only. Error: {e}")
        return {}

def resolve_nsx_path(path_list, group_map):
    """
    1. Checks if the Group Path has mapped IPs in 'group_map'.
    2. If yes, returns IPs.
    3. If no, returns the readable Group Name.
    """
    if not path_list:
        return "ANY"
    
    resolved_items = []
    for item in path_list:
        if item == "ANY":
            resolved_items.append("ANY")
        elif item in group_map:
            # FOUND! Use the actual IPs
            resolved_items.append(f"[{group_map[item]}]")
        else:
            # Not found (Dynamic Group?), just use the Name
            resolved_items.append(item.split('/')[-1])
            
    return ", ".join(resolved_items)

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
    parser = argparse.ArgumentParser(description="NSX-T Firewall Rule Export (With IP Resolution)")
    parser.add_argument('-s', '--server', required=True, help='NSX-T Manager IP')
    parser.add_argument('-u', '--username', required=True, help='NSX-T Username')
    parser.add_argument('-p', '--password', required=False, help='NSX-T Password')
    parser.add_argument('-o', '--output', required=False, help='Output CSV Filename')
    args = parser.parse_args()

    nsx_password = args.password or getpass.getpass(prompt=f'Password for {args.username}: ')
    
    session = requests.Session()
    session.auth = (args.username, nsx_password)

    print(f"🔄 Connecting to {args.server}...")
    
    # STEP 1: Pre-fetch Groups to build IP Map
    group_ip_map = get_group_ip_map(args.server, session)

    # STEP 2: Fetch Policies
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
            r_name = rule.get('display_name', 'N/A')
            r_id = rule.get('id', 'N/A')
            
            # --- UPDATED: Pass group_ip_map to resolver ---
            sources = resolve_nsx_path(rule.get('source_groups', []), group_ip_map)
            destinations = resolve_nsx_path(rule.get('destination_groups', []), group_ip_map)
            
            # Services/Profiles/Scope don't need IP resolution, just name cleaning
            services = resolve_nsx_path(rule.get('services', []), {}) 
            profiles = resolve_nsx_path(rule.get('profiles', []), {}) 
            applied_to = resolve_nsx_path(rule.get('scope', []), {})
            
            action = rule.get('action', 'ALLOW')
            is_disabled = rule.get('disabled', False)
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
    print(f"{'Name':<25} {'Sources (IPs if Static)':<30} {'Destinations (IPs if Static)':<30} {'Services':<10} {'Action':<8} {'Status':<10}")
    print("="*145)

    for item in export_data:
        if item["type"] == "POLICY_HEADER":
            print(f"\n📂 POLICY: {item['name']} ({item['count']} Rules)")
            print("-" * 145)
        else:
            # Truncate for display cleanliness
            src_disp = (item['Sources'][:27] + '..') if len(item['Sources']) > 27 else item['Sources']
            dst_disp = (item['Destinations'][:27] + '..') if len(item['Destinations']) > 27 else item['Destinations']
            
            print(f"{item['Name'][:24]:<25} {src_disp:<30} {dst_disp:<30} {item['Services'][:9]:<10} {item['Action']:<8} {item['Status']:<10}")

    # --- CSV Export ---
    if args.output:
        try:
            with open(args.output, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Policy Name', 'Rule Name', 'ID', 'Sources', 'Destinations', 'Services', 'Context Profiles', 'Applied To', 'Action', 'State'])
                for item in export_data:
                    if item["type"] == "RULE":
                        writer.writerow([
                            item['Policy'], item['Name'], item['ID'], 
                            item['Sources'],      # Contains IPs now
                            item['Destinations'], # Contains IPs now
                            item['Services'], item['Context Profiles'], 
                            item['Applied To'], item['Action'], item['Raw_Status']
                        ])
            print(f"\n✅ Exported to CSV: {args.output}")
        except Exception as e:
            print(f"❌ CSV Error: {e}")

if __name__ == "__main__":
    main()
