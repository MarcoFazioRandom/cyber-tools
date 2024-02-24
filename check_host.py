import sys
import requests
import json
from pprint import pprint
import time
import re
import os
import termcolor
from collections import Counter
import infinite_timer_loop
# sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) # Import utility.py from parent directory
import utility

HOSTNAMES = ['www.google.com',
			'www.bing.com']

CHECKTYPE = "http" # ping, http, tcp, dns, udp
MAX_NODES = 42 # the maximum number of nodes used for the check (default=42)
NODES = "" # a checking node(s)
TIMER_LOOP = 300
LOOPING = False

# termcolor check.
try:
	os.system('color')
except:
	pass

def curl(url, headers):
	result = {'status':-1, 'text':''}
	try:
		res = requests.get(url=url, headers=headers)
		result['status'] = res.status_code
		try:
			result['text'] = json.loads(res.text)
		except:
			result['text'] = res.text
		return result
	except Exception as e:
		print("error")
		return e

def get_nodes_results(text):
	r'''This func returns a list of strings with "node", <result>.
	"node, null" -> is still performing the check.
	"node, '[[null]]'" -> was unable to resolve the domain name.
	If completed:
	OK -> Successful
	TIMEOUT -> timeout
	MALFORMED -> malformed reply

	'"node", ' '[[
	["OK",0.065403938293457,"104.81.130.208"],
	["OK",0.0625400543212891]
	]]'
	'''
	regex_results = r'check_displayer\.display\(([^\)]+)\)'
	return re.findall(regex_results, text)

def print_nodes_status_http(message):
	unresolved_count = message.count('No such device or address')
	statuscodes = re.findall(r'"(\d\d\d)"', message)
	tot = unresolved_count + len(statuscodes)
	if tot == 0:
		print(termcolor.colored("error: zero packets", "red"))
		return
	
	# Convert statuscodes to category (200 to 2XX etc.)
	statuscodes_class = [code[:1]+"XX" for code in statuscodes]

	statuscodes_count_dict = dict(Counter(statuscodes))
	statuscodes_class_count_dict = dict(Counter(statuscodes_class))

	if unresolved_count > 0:
		statuscodes_count_dict["unresolved"] = unresolved_count
		statuscodes_class_count_dict["unresolved"] = unresolved_count
	
	color = "white"

	ok_count = statuscodes_class_count_dict.get("2XX", 0)
	redirect_count = statuscodes_class_count_dict.get("3XX", 0)
	error_count = statuscodes_class_count_dict.get("4XX", 0) + statuscodes_class_count_dict.get("5XX", 0)
	unresolved_count = statuscodes_class_count_dict.get("unresolved", 0)

	if ok_count >= tot*0.75:
		color = "green"
	elif error_count >= tot*0.5:
		color = "red"
	else:
		color = "yellow"
	
	result_string = f"{round(ok_count/tot, 2) * 100}% success, "
	result_string += f"tot={tot}, "
	result_string += str(statuscodes_count_dict)
	print(termcolor.colored(result_string, color))

def print_nodes_status_ping(message):
	unresolved_count = message.count('[[null]]')
	checking_count = message.count('null') - unresolved_count
	statuscodes = re.findall('(OK|TIMEOUT|MALFORMED)', message)
	statuscodes_count_dict = dict(Counter(statuscodes))
	tot = unresolved_count + checking_count + len(statuscodes)
	if unresolved_count > 0:
		statuscodes_count_dict["unresolved"] = unresolved_count
	if checking_count > 0:
		statuscodes_count_dict["still_checking"] = checking_count
	if tot == 0:
		print(termcolor.colored("error: zero packets", "red"))
		return
	color = "white"
	if statuscodes_count_dict.get("OK", 0) >= tot * 0.75:
		color = "green"
	elif statuscodes_count_dict.get("OK", 0) >= tot * 0.5:
		color = "yellow"
	else:
		color = "red"
	result_string = f"{round(statuscodes_count_dict['OK']/tot, 2) * 100}% success, "
	result_string += f"tot={tot}, "
	result_string += str(statuscodes_count_dict)
	print(termcolor.colored(result_string, color))

def get_redirected_url(host):
	new_host = host

	# Add http:// if absent.
	if host[0:4] != "http":
		new_host = "http://" + host

	new_host = requests.request(method="get", url=new_host).url

	if new_host != host:
		print(f"(redirected to {new_host})")
	
	return new_host

def check_host(host:str, checktype:str='ping', max_nodes:int=42, nodes:str=''):
	'''
	HOSTNAME = www.google.com.
	CHECKTYPE = ping, http, tcp, dns, udp.
	MAX_NODES = the maximum number of nodes used for the check.
	NODES = a checking node(s).
	'''

	print(f"checking {host}")

	host = get_redirected_url(host)

	url = f"https://check-host.net/check-{checktype}?host={host}"
	if max_nodes:
		url += f"&max_nodes={max_nodes}"
	if nodes:
		url += f"&node={nodes}"

	headers = {
		"Accept": "application/json"
	}

	# print("curl request\n")
	result = curl(url, headers)
	# pprint(result)

	if result["status"] != 200:
		print(termcolor.colored(f"check-host.net error: statuscode {result['status']}", "red"))
		print(url)
		return result

	try:
		# Get the link of the results.
		result["permanent_link"] = result['text'].get("permanent_link")
	except Exception as e:
		print(termcolor.colored(e, "red"))

	# Wait for the ping to finish.
	time.sleep(5)

	if not result["permanent_link"]:
		print(termcolor.colored("no results link", "red"))
		return
	
	# print("permament link: ", result["permanent_link"])

	report = curl(result["permanent_link"], headers)

	nodes_results_list = get_nodes_results(report.get("text", ""))
	if not nodes_results_list:
		print(termcolor.colored("no results founds", "red"))
		return
	# pprint(nodes_results_list)

	# print(f"{len(nodes_results_list)} nodes checked")

	if checktype == "ping":
		print_nodes_status_ping(str(nodes_results_list))
	elif checktype == "http":
		print_nodes_status_http(str(nodes_results_list))

def check_multiple_hosts(hosts:list, checktype:str='ping', max_nodes:int=42, nodes:str=''):
	for host in hosts:
		check_host(host, checktype, max_nodes, nodes)

def check_host_infinite_loop(timer_interval:float, host, checktype:str='ping', max_nodes:int=42, nodes:str=''):
	task = check_host
	if isinstance(host, list):
		task = check_multiple_hosts
	infinite_timer_loop.infinite_timer_loop(timer_interval, task, task_args=(host, checktype, max_nodes, nodes,))

def main():
	targets = HOSTNAMES
	checktype = CHECKTYPE
	max_nodes = MAX_NODES
	timer_loop = TIMER_LOOP

	print(f'targets:{targets} \nchecktype: {checktype} \nn of nodes: {max_nodes} \nloop: {LOOPING}')
	if LOOPING:
		print(f'run every {timer_loop} seconds.')
	print()

	if len(sys.argv) > 1:
		parameters = utility.parse_cmd_parameters(sys.argv, ["hostname", "checktype", "nodes", "loop"])
		targets = parameters.get("hostname", HOSTNAMES)
		checktype = parameters.get("checktype", CHECKTYPE)
		max_nodes = parameters.get("nodes", MAX_NODES)
		timer_loop = parameters.get("loop", TIMER_LOOP)

	if LOOPING or (len(sys.argv) > 1 and "-loop" in sys.argv):
		check_host_infinite_loop(timer_loop, targets, checktype, max_nodes)
	else:
		check_multiple_hosts(targets, checktype, max_nodes)

if __name__ == '__main__':
	main()
