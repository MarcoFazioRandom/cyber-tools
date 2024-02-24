import hashlib
import json
from pprint import pprint
import re
import datetime
import requests

def hash_dict(d:dict):
	hash = hashlib.md5(json.dumps(d, sort_keys=True).encode('utf-8')).hexdigest()
	return hash

def remove_dict_duplicates(list_of_dicts:list, key_to_check:str=None):
	hashed_dict = dict()
	for d in list_of_dicts:
		id = None
		if not key_to_check:
			id = hash_dict(d)
		else:
			id = d[key_to_check]
		hashed_dict[id] = d
	result = list()
	for v in hashed_dict.values():
		result.append(v)
	return result

def extract_date(text:str):
	date = re.search(r'\d\d\d\d-\d\d?-\d\d?', text)
	if date:
		date = date.group()
		date = datetime.strptime(date, r'%Y-%m-%d')
	else:
		date = ''
	return date

def parse_cmd_parameters(args:list, known_parameters:list, help_message:str=""):
	"Print helpmesssage if input is -h. Return a dict of parameter : value. \ninput: '-n 10 -host mypc' \noutput: {'n': '10', 'host': 'mypc'}"
	'''Usage:
		parameters = utility.parse_cmd_parameters(sys.argv, ["hostname", "checktype", "nodes"])
		target = parameters.get("hostname", HOSTNAME)
		checktype = parameters.get("checktype", CHECKTYPE)
		max_nodes = parameters.get("nodes", MAX_NODES)
	'''

	result = {}

	if len(args) == 0:
		return
	if len(args) == 1 and args[0] == "-h":
		print(help_message)
		return

	for par in known_parameters:
		par = "-" + str(par)
		if par in args:
			par_ind = args.index(par)
			if par_ind+1 < len(args):
				result[par.lstrip("-")] = args[par_ind+1]
	return result
