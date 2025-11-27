# dfw-rule-stats.py
Retrieves rule statistics, formats them into a readable table grouped by Policy, and optionally saves to CSV.

Command:

python3 dfw-rule-stats.py -s <NSX_IP> -u <USERNAME> -o <OUTPUT_FILE>

Arguments:

  -h, --help            show this help message and exit
  
  -s SERVER, --server SERVER
                        -> NSX Manager IP/FQDN
  
  -u USERNAME, --username USERNAME
                        -> NSX Username
  
  -p PASSWORD, --password PASSWORD
                        -> NSX Password (optional)
  
  -o OUTPUT, --output OUTPUT
                        -> Output CSV filename (e.g. stats.csv)

