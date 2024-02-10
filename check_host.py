import sys
import requests
import json
from pprint import pprint
import time
import re
import os
import termcolor
from collections import Counter

HOSTNAME = "https://www.google.com"
CHECKTYPE = "http" # ping, http, tcp, dns, udp
MAX_NODES = 42 # the maximum number of nodes used for the check (default=42)
NODES = "" # a checking node(s)

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
	statuscodes_count = dict(Counter(statuscodes))
	statuscodes_count["unresolved"] = unresolved_count
	color = "white"
	if statuscodes_count["200"] >= tot * 0.75:
		color = "green"
	elif statuscodes_count["200"] >= tot * 0.5:
		color = "yellow"
	else:
		color = "red"
	result_string = f"{round(statuscodes_count['200']/tot, 2) * 100}% success, "
	result_string += f"tot={tot}, "
	result_string += str(statuscodes_count)
	print(termcolor.colored(result_string, color))

def print_nodes_status_ping(message):
	unresolved_count = message.count('[[null]]')
	checking_count = message.count('null') - unresolved_count
	statuscodes = re.findall('(OK|TIMEOUT|MALFORMED)', message)
	statuscodes_count = dict(Counter(statuscodes))
	tot = unresolved_count + checking_count + len(statuscodes)
	statuscodes_count["unresolved"] = unresolved_count
	statuscodes_count["still_checking"] = checking_count
	if tot == 0:
		print(termcolor.colored("error: zero packets", "red"))
		return
	color = "white"
	if statuscodes_count["OK"] >= tot * 0.75:
		color = "green"
	elif statuscodes_count["OK"] >= tot * 0.5:
		color = "yellow"
	else:
		color = "red"
	result_string = f"{round(statuscodes_count['OK']/tot, 2) * 100}% success, "
	result_string += f"tot={tot}, "
	result_string += str(statuscodes_count)
	print(termcolor.colored(result_string, color))

def check_host(host:str, checktype:str='ping', max_nodes:int=42, nodes:str=''):
	'''
	HOSTNAME = www.google.com.
	CHECKTYPE = ping, http, tcp, dns, udp.
	MAX_NODES = the maximum number of nodes used for the check.
	NODES = a checking node(s).
	'''

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
		return result

	try:
		# Get the link of the results.
		result["permanent_link"] = result['text'].get("permanent_link")
	except Exception as e:
		print(termcolor.colored(e, "red"))

	# Wait for the ping to finish.
	time.sleep(5)

	report = curl(result["permanent_link"], headers)

	nodes_results_list = get_nodes_results(report["text"])
	# pprint(nodes_results_list)

	# print(f"{len(nodes_results_list)} nodes checked")

	if checktype == "ping":
		print_nodes_status_ping(str(nodes_results_list))
	elif checktype == "http":
		print_nodes_status_http(str(nodes_results_list))

def main():
	target = ""

	if len(sys.argv) == 1:
		target = input("Input a hostname or ip to check:\n")
	
	if not target:
		target = HOSTNAME

	check_host(target, CHECKTYPE, MAX_NODES, NODES)

if __name__ == '__main__':
	main()
