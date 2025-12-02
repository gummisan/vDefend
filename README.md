# dfw-rule-stats-v2.py
Retrieves rule statistics, formats them into a readable table grouped by Policy, and optionally saves to CSV.

Command:

   python3 dfw-rule-stats-v2.py --server <NSX_IP> --username <USERNAME> --output <OUTPUT_FILE>

Arguments:

  -h, --help            show this help message and exit\
  -s SERVER, --server SERVER
                        -> NSX Manager IP/FQDN\
  -u USERNAME, --username USERNAME
                        -> NSX Username\
  -p PASSWORD, --password PASSWORD
                        -> NSX Password (optional)\
  -o OUTPUT, --output OUTPUT
                        -> Output CSV filename (e.g. stats.csv)

Sample output:

   <img width="951" height="633" alt="image" src="https://github.com/user-attachments/assets/1cf84a3b-64d6-41d8-9187-830b12cb271f" />



   

    

  
