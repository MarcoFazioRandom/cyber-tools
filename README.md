# Summary
hunt.py is the main class.
ports_scanner.py is just for testing open ports of an IP.
scan_tools.py has the methods to scan and search the target with API modules.

# How to use
If you want to hunt for only IP, you can just execute hunt.py followed by the target IP from the cmd and the result will be printed in the terminal.
> python hunt.py 8.8.8.8 

If you want to hunt for many IP, write them all in input.txt, then run hunt.py without arguments, the results will be written in output.csv.
> python hunt.py

# Note
- The file can take URL (e.g. www.google.com), the script will try to take the host IP.
- AbuseIPDB will take the results from the last 30 days.
- The scripts will only scan the common ports defined in scan_tools.py.
- The key used for the AbuseIPDB API is from a free account so it has a max of 1,000 IP Checks & Reports / Day.
