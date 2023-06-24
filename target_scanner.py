import os
import sys
import json
import termcolor
import socket
from threading import Thread
from queue import Queue
import time
import csv
import cybertools
import ports_scanner

'''
This script can be called with a target argument "python list_scanner.py 8.8.8.8" or with the name of a file "python list_scanner.py -f input.txt"
'''

results_keys = ["target", "type", "subtype", "virustotal_type", "virustotal_score", "name", "abuseConfidenceScore", "isPublic", "isWhitelisted", "countryCode", "usageType", "isp", "domain", "hostnames", "totalReports", "lastReportedAt", "lastComment"]

def get_targets_from_file(file:str):
	complete_filepath = os.path.join(os.getcwd(), file)
	lines = []
	with open(complete_filepath, "r") as f:
		for l in f.readlines():
			if l.split(): 
				lines.append(l.strip())
	return lines

def scan_target(target:str, q:Queue=None):
	result = dict()

	result["target"] = target

	target_type = cybertools.get_type(target)
	result.update(target_type)

	# host_ip = None
	# try:
	# 	host_ip = socket.gethostbyname(target)
	# except:
	# 	pass
	# result["host_ip"] = host_ip

	# result["ping"] = cybertools.ping(target)

	result.update(cybertools.abuseipdb_check(target))

	result.update(cybertools.virustotal_check(target_type['virustotal_type'], target))

	# if result["type"] == "ip" and result["isPublic"]:
	# 	result["open_ports"] = ports_scanner.test_ports(target)

	if q:
		q.put(result)
	
	return result

def file_writer(filepath, q):
	complete_filepath = os.path.join(os.getcwd(), filepath)
	# Clear the file.
	open(complete_filepath, 'w').close()
	found_count = 0
	with open(complete_filepath, "a", newline="") as file_output:
		writer = csv.DictWriter(file_output, fieldnames=results_keys, restval="-")
		while True:
			line = q.get()
			if line is None:
				break
			else:
				found_count += 1
			if found_count == 1:
				writer.writeheader()
			new_row = {k:line.get(k, '') for k in results_keys}
			writer.writerow(new_row)
			file_output.flush()
			q.task_done()
	q.task_done()

def scan_from_list(targets:list):
	old_tot = len(targets)
	targets = list(set(targets))
	tot = len(targets)
	print(f'targets to scan: {tot}, duplicates found: {old_tot - tot}')

	q = Queue()

	start_time = time.time()
	
	writer_thread = Thread(target=file_writer, args=("output.csv", q), daemon=True)
	writer_thread.start()
	
	threads = [Thread(target=scan_target, args=(i, q)) for i in targets]

	for thread in threads:
		thread.start()
	for thread in threads:
		thread.join()
	
	q.put(None)
	q.join()

	elapsed_time = time.time() - start_time

	print(f"finished in {round(elapsed_time, 4)} s.")

def main():
	try:
		os.system('color')
	except:
		pass

	if len(sys.argv) == 1:
		print(termcolor.colored("No arguments!", "red"))
		return
	elif len(sys.argv) == 2:
		print(f"hunting {sys.argv[1]}")
		result = scan_target(sys.argv[1])
		print(json.dumps(result, default=str, indent=2))
	elif len(sys.argv) == 3 and sys.argv[1] == '-f':
		targets_list = get_targets_from_file(sys.argv[2])
		scan_from_list(targets_list)
	else:
		print(termcolor.colored("Invalid arguments!", "red"))

if __name__ == '__main__':
	main()
