## Scripts:
- cybertools: a collection of functions that use the APIs of cybersecurity tools like abuseipdb, virustotal, shodan, whois.
- ports_scanner: a script to scan the open ports of an ip.
- target_scanner: the main script, used to scan one target, or multiple targets taken from a txt file, it outputs a csv with the result.
- phishing_url_scanner.py: a script that analyzes a url, it extracts the domains, the emails and decodes the substring encoded in base64.

#### target_scanner: 
This script can be called with a single target argument: 
`python list_scanner.py 8.8.8.8` 
or with -f + the name of a file 
`python list_scanner.py -f input.txt`
