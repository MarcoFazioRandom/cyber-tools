# Cyberscan

# Summary
This script can scan IPs (v4 and v6), domains, file hashes and urls. 
It will detect the type automatically, when scanning an IP or domain, if it starts with "https://" it will be detected as an URL. 
The ioc will be deobfuscated automatically.
To use AbuseIpDb and VirusTotal API, write your API key in the file settings.py

--- 

# Requirements
Run this command to install the required modules:
`pip install -r requirements.txt`

If you get an error for a conflict, try uninstall and reinstalling the module.

--- 

# How to use
You can scan a single ioc:
`python soc_scan.py 8.8.8.8`
or
multiple iocs listed in a txt file using the argument -f
`python soc_scan.py -f input.txt`

In the latter case, in the "/output/" folder, the script will create a csv file for each type of ioc.

