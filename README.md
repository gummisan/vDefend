# dfw-rule-stats-v3.py
Retrieves rule statistics, formats them into a readable table grouped by Policy, and optionally saves to CSV.

Command:

   python3 dfw-rule-stats-v3.py --server <NSX_IP> --username <USERNAME> --output <OUTPUT_FILE>

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

  <img width="1017" height="636" alt="image" src="https://github.com/user-attachments/assets/003c5338-c47f-4536-8eb1-c595ff99e24a" />

#Offline Method
If the jump server does not have access to Internet, follow the steps below. 

1. On a Linux machine with internet access, create a folder named "pythonmodules" under ~ directory. change directory to ~/pythonmodules and create requirements.txt file with the following content
   root@docker-01:~/pythonmodules# cat requirements.txt
      certifi==2025.11.12
      charset-normalizer==3.4.4
      DateTime==6.0
      idna==3.11
      pytz==2025.2
      requests==2.32.5
      urllib3==2.5.0
      zope.interface==8.1.1

2. Download the python modules listed in the requirements.txt file using the following command
   root@docker-01:~/pythonmodules# pip download -r requirements.txt -d ~/pythonmodules/

3. Ensure that the python modules are downloaded
   root@docker-01:~/pythonmodules# ls -l
      requirements.txt
      certifi-2025.11.12-py3-none-any.whl
      charset_normalizer-3.4.4-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl
      datetime-6.0-py3-none-any.whl
      idna-3.11-py3-none-any.whl
      pytz-2025.2-py2.py3-none-any.whl
      requests-2.32.5-py3-none-any.whl
      urllib3-2.5.0-py3-none-any.whl
      zope_interface-8.1.1-cp312-cp312-manylinux1_x86_64.manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_5_x86_64.whl

4. Copy the content under ~/pythonmodules to the airpgapped jump server which does not have internet access under the same folder structure
   root@docker-02:~/pythonmodules# ls -l
      requirements.txt
      certifi-2025.11.12-py3-none-any.whl
      charset_normalizer-3.4.4-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl
      datetime-6.0-py3-none-any.whl
      idna-3.11-py3-none-any.whl
      pytz-2025.2-py2.py3-none-any.whl
      requests-2.32.5-py3-none-any.whl
      urllib3-2.5.0-py3-none-any.whl
      zope_interface-8.1.1-cp312-cp312-manylinux1_x86_64.manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_5_x86_64.whl

5. Initiate a python virtual enviroment on the airgapped jump server
   root@docker-02:~/pythonmodules# python3 -m venv ~/venv1
   root@docker-02:~/pythonmodules# source ~/venv1/bin/activate
   (venv1) root@docker-02:~/pythonmodules#

6. Install the python modules
   (venv1) root@docker-02:~/pythonmodules# pip install -r requirements.txt --no-index --find-links ~/pythonmodules/

7. Verify that python modules are installed
   (venv1) root@docker-02:~/pythonmodules# pip list
      Package            Version
      ------------------ ----------
      certifi            2025.11.12
      charset-normalizer 3.4.4
      DateTime           6.0
      idna               3.11
      pip                24.0
      pytz               2025.2
      requests           2.32.5
      urllib3            2.5.0
      zope.interface     8.1.1

8. Now run the dfw-rule-stats-v3.py script
   (venv1) root@docker-02:~/pythonmodules# python3 dfw-rule-stats-v3.py --server 10.1.1.20 --username admin --output dfwstats.csv
  


   

   



   

    

  
