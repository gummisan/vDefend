import requests
import urllib3
import getpass
import argparse
import csv
import sys

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_group_mapping(session, base_url):
    """Fetches all groups to map their immutable IDs to their current Display Names"""
    mapping = {}
    try:
        resp = session.get(f"{base_url}/domains/default/groups")
        if resp.status_code == 200:
            for g in resp.json().get('results', []):
                group_id = g.get('id')
                display_name = g.get('display_name')
                if group_id and display_name:
                    mapping[group_id] = display_name
    except Exception:
        pass
    return mapping

def format_paths(paths, mapping, is_scope=False):
    """Translates raw API paths into human-readable Display Names"""
    if not paths: return "DFW" if is_scope else "ANY"
    names = []
    for p in paths:
        if p.upper() == "ANY": 
            names.append("DFW" if is_scope else "ANY")
        elif 'is_dfw' in p.lower(): 
            names.append("DFW")
        else:
            group_id = p.split('/')[-1]
            names.append(mapping.get(group_id, group_id))
    return ", ".join(names)

def fetch_rule_vms(session, base_url, rule):
    """Calculates Active VMs based strictly on the 'Applied To' (Scope) field logic"""
    scope_groups = rule.get('scope', [])
    
    is_global = not scope_groups or any('is_dfw' in g.lower() or 'any' in g.lower() for g in scope_groups)
    
    if is_global:
        return ["ALL VMs (Global NSX Scope)"]

    all_member_vms = []
    for group_path in scope_groups:
        group_id = group_path.split('/')[-1]
        member_url = f"{base_url}/domains/default/groups/{group_id}/members/virtual-machines"
        mem_resp = session.get(member_url)
        
        if mem_resp.status_code == 200:
            vms = mem_resp.json().get('results', [])
            all_member_vms.extend([v.get('display_name') for v in vms])
            
    return sorted(list(set(all_member_vms)))

def print_dynamic_table(data_dicts, columns):
    """Dynamically sizes columns based on the longest string in the dataset"""
    if not data_dicts:
        return

    # 1. Calculate the maximum width required for each column
    col_widths = {col: len(col) for col in columns}
    for row in data_dicts:
        for col in columns:
            val = str(row.get(col, "N/A"))
            if len(val) > col_widths[col]:
                col_widths[col] = len(val)

    # 2. Build the dynamic format string (e.g., "{Policy:<15} | {Source:<25}")
    format_parts = [f"{{{col}:<{col_widths[col]}}}" for col in columns]
    format_str = " | ".join(format_parts)
    
    # 3. Print Header and Separator
    header_data = {col: col.upper() for col in columns}
    total_width = sum(col_widths.values()) + (len(columns) - 1) * 3
    
    print("\n" + format_str.format(**header_data))
    print("-" * total_width)
    
    # 4. Print Data Rows
    for row in data_dicts:
        safe_row = {col: str(row.get(col, "N/A")) for col in columns}
        print(format_str.format(**safe_row))
    print("-" * total_width)

def export_to_csv(data, filename, global_vms):
    if not filename.endswith('.csv'): filename += '.csv'
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=["Policy", "Rule Name", "Rule ID", "Source", "Destination", "Services", "Profiles", "Applied To", "Action", "Active VMs"])
            writer.writeheader()
            writer.writerows(data)
            
            if global_vms:
                csv_append = csv.writer(file)
                csv_append.writerow([]) 
                csv_append.writerow(["IDPS Enabled VMs"]) 
                for vm in sorted(list(global_vms)):
                    csv_append.writerow([vm])
                    
        print(f"[+] Successfully exported {len(data)} rules to '{filename}'")
    except Exception as e:
        print(f"[!] Failed to write CSV: {e}")

def list_all_rules(session, base_url, cli_output_file, group_mapping):
    print(f"\n[*] Fetching all IDPS policies...")
    policies_resp = session.get(f"{base_url}/domains/default/intrusion-service-policies")
    policies_resp.raise_for_status()
    policies = policies_resp.json().get('results', [])

    all_rules_data = []
    global_active_vms = set()

    for policy in policies:
        policy_name = policy.get('display_name', 'N/A')
        policy_id = policy.get('id')
        
        rules = policy.get('rules', [])
        if not rules:
            detail_resp = session.get(f"{base_url}/domains/default/intrusion-service-policies/{policy_id}")
            if detail_resp.status_code == 200:
                rules = detail_resp.json().get('rules', [])

        for rule in rules:
            rule_name = rule.get('display_name', 'N/A')
            rule_id = str(rule.get('rule_id') or rule.get('id', 'N/A'))
            action = rule.get('action', 'N/A')
            
            src_disp = format_paths(rule.get('source_groups', []), group_mapping)
            dst_disp = format_paths(rule.get('destination_groups', []), group_mapping)
            scope_disp = format_paths(rule.get('scope', []), group_mapping, is_scope=True)
            svc_disp = format_paths(rule.get('services', []), group_mapping)
            prof_disp = ", ".join([p.split('/')[-1] for p in rule.get('ids_profiles', [])]) if rule.get('ids_profiles') else "N/A"

            active_vm_list = fetch_rule_vms(session, base_url, rule)
            active_vms_str = ", ".join(active_vm_list) if active_vm_list else "No Active VMs"

            for vm in active_vm_list:
                if "ALL VMs" not in vm:
                    global_active_vms.add(vm)
            
            # Save data to dictionary instead of printing immediately
            all_rules_data.append({
                "Policy": policy_name, "Rule Name": rule_name, "Rule ID": rule_id, 
                "Source": src_disp, "Destination": dst_disp, "Services": svc_disp, 
                "Profiles": prof_disp, "Applied To": scope_disp, "Action": action, "Active VMs": active_vms_str
            })

    # Print the perfectly aligned table
    columns_to_print = ["Policy", "Rule Name", "Rule ID", "Source", "Destination", "Services", "Profiles", "Applied To", "Action", "Active VMs"]
    print_dynamic_table(all_rules_data, columns_to_print)

    if cli_output_file:
        export_to_csv(all_rules_data, cli_output_file, global_active_vms)
    else:
        ans = input("Would you like to export these results to a CSV file? (y/n): ").strip().lower()
        if ans == 'y':
            filename = input("Enter filename (default: idps_export.csv): ").strip() or "idps_export.csv"
            export_to_csv(all_rules_data, filename, global_active_vms)

def search_by_vm(session, base_url, group_mapping):
    search_vm = input("\nEnter VM Name to search (e.g., idps-01): ").strip()
    if not search_vm:
        print("[!] VM name cannot be empty.")
        return

    print(f"[*] Looking up VM '{search_vm}'...")
    vm_resp = session.get(f"{base_url}/realized-state/virtual-machines")
    vms = vm_resp.json().get('results', [])
    target = next((v for v in vms if v['display_name'].lower() == search_vm.lower()), None)
    
    if target:
        ext_id = target.get('external_id')
        assoc_resp = session.get(f"{base_url}/virtual-machine-group-associations", params={'vm_external_id': ext_id})
        member_group_ids = [g.get('path').split('/')[-1] for g in assoc_resp.json().get('results', []) if g.get('path')]
        display_names = [group_mapping.get(gid, gid) for gid in member_group_ids]
        print(f"[+] VM '{search_vm}' is a member of groups: {', '.join(display_names)}")
    else:
        print(f"[!] VM '{search_vm}' not found in realized state.")
        return

    print(f"[*] Fetching IDPS policies...")
    policies_resp = session.get(f"{base_url}/domains/default/intrusion-service-policies")
    policies = policies_resp.json().get('results', [])

    matched_rules_data = []

    for policy in policies:
        policy_name = policy.get('display_name', 'N/A')
        policy_id = policy.get('id')
        
        rules = policy.get('rules', [])
        if not rules:
            detail_resp = session.get(f"{base_url}/domains/default/intrusion-service-policies/{policy_id}")
            if detail_resp.status_code == 200:
                rules = detail_resp.json().get('rules', [])
        
        for rule in rules:
            rule_id = str(rule.get('rule_id') or rule.get('id', 'N/A'))
            action = rule.get('action', 'N/A')

            raw_src = rule.get('source_groups', [])
            raw_dst = rule.get('destination_groups', [])
            raw_scope = rule.get('scope', [])

            src_ids = [s.split('/')[-1] for s in raw_src]
            dst_ids = [d.split('/')[-1] for d in raw_dst]
            scope_ids = [s.split('/')[-1] for s in raw_scope]

            match_src = any(g in src_ids for g in member_group_ids) or not src_ids or "ANY" in [s.upper() for s in src_ids]
            match_dst = any(g in dst_ids for g in member_group_ids) or not dst_ids or "ANY" in [d.upper() for d in dst_ids]
            
            is_global_scope = not scope_ids or any('is_dfw' in s.lower() or 'any' in s.lower() for s in scope_ids)
            match_scope = any(g in scope_ids for g in member_group_ids) or is_global_scope

            if (match_src or match_dst) and match_scope:
                src_disp = format_paths(raw_src, group_mapping)
                dst_disp = format_paths(raw_dst, group_mapping)
                scope_disp = format_paths(raw_scope, group_mapping, is_scope=True)
                svc_disp = format_paths(rule.get('services', []), group_mapping)
                prof_disp = ", ".join([p.split('/')[-1] for p in rule.get('ids_profiles', [])]) if rule.get('ids_profiles') else "N/A"
                
                # Append to our list instead of printing
                matched_rules_data.append({
                    "Policy": policy_name, "Rule Name": rule.get('display_name', 'N/A'), "Rule ID": rule_id, 
                    "Source": src_disp, "Destination": dst_disp, "Services": svc_disp, 
                    "Profiles": prof_disp, "Applied To": scope_disp, "Action": action
                })

    if not matched_rules_data:
        print("[!] No active IDPS rules found for this VM.")
    else:
        # Print the dynamically sized table for the matched rules
        columns_to_print = ["Policy", "Rule Name", "Rule ID", "Source", "Destination", "Services", "Profiles", "Applied To", "Action"]
        print_dynamic_table(matched_rules_data, columns_to_print)

def main():
    parser = argparse.ArgumentParser(description="NSX IDPS Integrated Management Tool")
    parser.add_argument("--server", help="NSX Manager FQDN/IP")
    parser.add_argument("--username", help="Username")
    parser.add_argument("--password", help="Password (optional)")
    parser.add_argument("--output", help="Output CSV file for Option 1")
    args = parser.parse_args()
    
    nsx_host = args.server or input("NSX Manager FQDN/IP: ").strip()
    username = args.username or input("Username: ").strip()
    password = args.password or getpass.getpass(f"Enter password for {username}@{nsx_host}: ")
    cli_output = args.output
    
    base_url = f"https://{nsx_host}/policy/api/v1/infra"

    try:
        session = requests.Session()
        session.auth = (username, password)
        session.verify = False 
        session.get(f"{base_url}/realized-state/virtual-machines").raise_for_status()

        print(f"[*] Building mapping dictionary for Group Display Names...")
        group_mapping = get_group_mapping(session, base_url)

        while True:
            print("\n" + "="*45)
            print("1. List All IDPS Rules & Active VMs")
            print("2. Search IDPS Rules for a Specific VM")
            print("3. Exit")
            choice = input("Select an option (1-3): ").strip()

            if choice == '1':
                list_all_rules(session, base_url, cli_output, group_mapping)
            elif choice == '2':
                search_by_vm(session, base_url, group_mapping)
            elif choice == '3' or choice == 'exit':
                print("Exiting tool. Goodbye!")
                break
            else:
                print("[!] Invalid choice.")

    except requests.exceptions.HTTPError as err:
        print(f"\n[!] HTTP Error: {err.response.status_code}. Verify your credentials.")
    except Exception as e:
        print(f"\n[!] Connection Error: {e}")

if __name__ == "__main__":

    main()
