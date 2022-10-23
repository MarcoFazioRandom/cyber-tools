import threading
import os
from queue import Queue
import scan_tools
import csv
import time
import socket
import termcolor
import sys
import json
import re

def get_file_path(filename):
	return os.path.dirname(os.path.abspath(__file__)) + "\\" + filename

def task_writer(q):
	clear_file("output.csv")
	complete_filepath = get_file_path("output.csv")
	found_count = 0
	with open(complete_filepath, "a", newline="") as file:
		while True:
			result = q.get()
			if result is None:
				break
			else:
				found_count += 1
			writer = csv.DictWriter(file, fieldnames=result.keys(), restval="-")
			if found_count == 1:
				writer.writeheader()
			writer.writerow(result)
			file.flush()
			q.task_done()
	q.task_done()
	print(f"{found_count} matches found.")

def task_hunt(target, q=None):
	result = dict()
	result["target"] = target = re.sub(r"https?:\/\/", "", target).rstrip(r"/")
	host_ip = None
	try:
		host_ip = socket.gethostbyname(target)
	except:
		termcolor.cprint(f"{target} \t error", "yellow")
		return
	result["host_ip"] = host_ip
	result["ping"] = scan_tools.ping(target)
	result.update(scan_tools.abuseipdb_scan(host_ip))
	result.update(scan_tools.whois_scan(target))
	result.update(scan_tools.shodan_scan(target))
	result["open_ports"] = scan_tools.open_ports_scan(target)
	found = result["ping"] or result["abuseConfidenceScore"] > 0 or result["open_ports"]
	if found:
		termcolor.cprint(f"{target} \t found", "green")
		if q:
			q.put(result)
	else:
		termcolor.cprint(f"{target} \t not found", "red")
	if not q:
		return result

def clear_file(filename):
	complete_filepath = get_file_path(filename)
	with open(complete_filepath, "r+") as file:
		file.truncate(0)

def open_input_file():
	complete_filepath = get_file_path("input.txt")
	lines = []
	with open(complete_filepath, "r") as f:
		for l in f.readlines():
			if l.split(): 
				lines.append(l.strip())
	return lines

def start_hunt():
	# clear_file("output.csv")

	target_list = open_input_file()

	# Delete duplicates 
	target_list = list(set(target_list))

	print(f"{len(target_list)} targets to scan")

	q = Queue()

	start_time = time.time()
	
	writer_thread = threading.Thread(target=task_writer, args=(q,), daemon=True)
	writer_thread.start()

	threads = []
	
	for i in range(len(target_list)):
		threads.append(threading.Thread(target=task_hunt, args=(target_list[i], q)))
	for thread in threads:
		thread.start()
	for thread in threads:
		thread.join()
	
	q.put(None)
	q.join()

	elapsed_time = time.time() - start_time

	print(f"finished in {round(elapsed_time, 4)} s.")

if len(sys.argv) == 1:
	start_hunt()
elif len(sys.argv) == 2:
	print(f"hunting {sys.argv[1]}... ")
	result = task_hunt(sys.argv[1])
	print(json.dumps(result, default=str, indent=4))
