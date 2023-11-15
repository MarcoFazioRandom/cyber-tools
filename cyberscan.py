import os
import sys
import termcolor
from pprint import pprint
import cybertools
import myregex
import pandas
from threading import Thread
from queue import Queue

def get_targets_from_file(file:str):
	complete_filepath = os.path.join(os.getcwd(), file)
	lines = []
	with open(complete_filepath, "r") as f:
		for l in f.readlines():
			if l.split(): 
				lines.append(l.strip())
	lines = list(set(lines))
	return lines

def get_target_information(target:str, whois:bool=False, abuseipdb:bool=False, virustotal:bool=False, shodan:bool=False, q:Queue=None):
	target_type = myregex.get_type(target)
	if not target_type['type']:
		# Try to remove obfuscations.
		target = cybertools.deobfuscate(target)
		target_type = myregex.get_type(target)
		if not target_type['type']:
			print(termcolor.colored(f"{target} : type not found.", "red"), "\n")
			return dict()

	result = dict()
	result["target"] = target
	result.update(target_type)
	if whois:
		if target_type['type'] == 'ip':
			r = cybertools.whois_ip(target)
			for k,v in r.items():
				result[f"whois_{k}"] = v
		elif target_type['type'] == 'domain':
			r = cybertools.whois_domain(target)
			for k,v in r.items():
				result[f"whois_{k}"] = v
	if abuseipdb and target_type['type'] == 'ip':
		r = cybertools.abuseipdb_check(target)
		for k,v in r.items():
			result[f"abuseipdb_{k}"] = v
	if virustotal:
		r = cybertools.virustotal_check(target)
		for k,v in r.items():
			result[f"virustotal_{k}"] = v
	if shodan and target_type['type'] == 'ip':
		r = cybertools.shodan_check(target)
		for k,v in r.items():
			result[f"shodan_{k}"] = v
	
	if q:
		q.put(result)
	
	return result

def write_csv(filename:str, ioc_list:list):
	dataframe = pandas.DataFrame(ioc_list)
	dataframe.to_csv(filename, index=False, encoding='utf-8')

def scan_with_multithread(targets_list:list, selected_whois:bool=False, selected_abuseipdb:bool=False, selected_virustotal:bool=False, selected_shodan:bool=False):
	threads = []

	queue_results = Queue()

	for target in targets_list:
		threads.append(Thread(target=get_target_information, args=(target, selected_whois, selected_abuseipdb, selected_virustotal, selected_shodan, queue_results,)))

	for t in threads:
		t.start()

	for t in threads:
		t.join()

	queue_results.put(None)

	scan_results_by_type = dict()

	while True:
		q = queue_results.get()
		queue_results.task_done()
		if q is None:
			break
		else:
			print(termcolor.colored(q["target"], "cyan"))
			pprint(q)
			print()
			if not scan_results_by_type.get(q["type"]):
				scan_results_by_type[q["type"]] = list()
			scan_results_by_type[q["type"]].append(q)

	for k,v in scan_results_by_type.items():
		write_csv(f"output/output_{k}.csv", v)
		print(termcolor.colored(f"created file output_{k}.csv", "green"))

def scan_multiple_targets(targets_list:list, selected_whois:bool=False, selected_abuseipdb:bool=False, selected_virustotal:bool=False, selected_shodan:bool=False):
	scan_results_by_type = dict()
	for target in targets_list:
		target_info = get_target_information(target, selected_whois, selected_abuseipdb, selected_virustotal, selected_shodan)

		if not target_info:
			continue

		if target_info.get("abuseipdb_status") and (target_info["abuseipdb_status"] == 401 or target_info["abuseipdb_status"] == 429):
			print(termcolor.colored("abuseipdb error: " + str(target_info["abuseipdb_status"]), "red"))
			selected_abuseipdb = False
		if target_info.get("virustotal_status") and (target_info["virustotal_status"] == 401 or target_info["virustotal_status"] == 429):
			print(termcolor.colored("virustotal error: " + str(target_info["virustotal_status"]), "red"))
			selected_virustotal = False

		print(termcolor.colored(target, "cyan"))
		pprint(target_info)
		print()

		if not scan_results_by_type.get(target_info["type"]):
			scan_results_by_type[target_info["type"]] = list()
		scan_results_by_type[target_info["type"]].append(target_info)

	for k,v in scan_results_by_type.items():
		write_csv(f"output/output_{k}.csv", v)

def main():
	# termcolor check
	try:
		os.system('color')
	except:
		pass

	if len(sys.argv) == 1:
		print(termcolor.colored("No arguments.", "red"))
		return
	elif len(sys.argv) == 2:
		target = sys.argv[1]
		result = get_target_information(target, True, True, True, True)
		pprint(result)
	elif len(sys.argv) == 3 and sys.argv[1] == '-f':
		print("Select service you want to use: \n1) WhoIs. \n2) AbuseIPDB analysis. \n3) VirusTotal analysis.\n4) Shodan. \n5) Everything.")
		inp = input()
		try:
			inp = int(inp)
		except ValueError:
			print(termcolor.colored("Invalid input.", "red"))
			return
		
		selected_whois = False
		selected_abuseipdb = False
		selected_virustotal = False
		selected_shodan = False
		if inp == 1:
			selected_whois = True
		elif inp == 2:
			selected_abuseipdb = True
		elif inp == 3:
			selected_virustotal = True
		elif inp == 4:
			selected_shodan = True
		elif inp == 5:
			selected_whois = True
			selected_abuseipdb = True
			selected_virustotal = True
			selected_shodan = True
		else:
			print(termcolor.colored("Invalid input.", "red"))
			return
		
		targets_list = get_targets_from_file(sys.argv[2])

		print(f"targets to scan: {len(targets_list)}")

		# scan_multiple_targets(targets_list, selected_whois, selected_abuseipdb, selected_virustotal, selected_shodan)

		scan_with_multithread(targets_list, selected_whois, selected_abuseipdb, selected_virustotal, selected_shodan)
	else:
		print(termcolor.colored("Invalid cmd arguments.", "red"))

if __name__ == '__main__':
	main()
