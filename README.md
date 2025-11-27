# dfw-rule-stats.py
Usage: python3 dfw-rule-stats.py --server 10.1.1.20 --username admin -o stats.csv

usage: dfwcopy.py [-h] --nsx NSX --user USER [--password PASSWORD] --file FILE [--export] [--prefix PREFIX] [--prefixrules] [--anchor ANCHOR] [--position {insert_before,insert_after}]
                  [--output OUTPUT] [--logfile LOGFILE] [--retries RETRIES] [--undo] [--apply APPLY]
optional arguments:
-h, --help            show this help message and exit
--nsx NSX             Target NSX Manager
--user USER           NSX User
--password PASSWORD   NSX User password
--file FILE           Input File, or output to export config
--export              If specified, call H-API to the NSX Manager to export configs that can be used for migration
--prefix PREFIX       Prefix to append to all object names and IDs
