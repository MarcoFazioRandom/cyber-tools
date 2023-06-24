import os
from datetime import datetime
import requests
import whois
import shodan
import json
import re

# dates can be one date or a list of date, this function returns the most recent date.
def convert_dates(dates):
	if not dates:
		return ""
	if isinstance(dates, datetime):
		return dates.strftime(f"%Y-%m-%d")
	elif isinstance(dates, list):
		dates = [d.strftime(f"%Y-%m-%d") for d in dates]
		dates = sorted(dates, reverse=True)
		return dates[0]

def ping(target):
	return not os.system(f"ping {target} -n 1 > NUL")
	# stream = os.popen(f"ping {target} -n 1")
	# output = stream.read()
	# return output

_SHODAN_API_KEY = "KEY"

SHODAN_KEYS = ["org", "hostnames", "domains", "C", "country_name", "city", "os", "isp", "last_update"]

def shodan_check(ip):
	result = {k:None for k in SHODAN_KEYS}
	api = shodan.Shodan(_SHODAN_API_KEY)
	try:
		host = api.host(ip)
		
		result = {k:host.get(k, result[k]) for k in SHODAN_KEYS}
	except Exception as e:
		result["error"] = e
	return result

WHOIS_KEYS = ["domain_name", "registrar", "whois_server", "referral_url", "creation_date", "updated_date", "expiration_date", "name_servers", "emails", "org", "country"]

# Whois
def whois_check(target):
	result = {k:None for k in WHOIS_KEYS}
	try:
		w = whois.whois(target)
		result = {k:w.get(k, result[k]) for k in WHOIS_KEYS}
	except Exception as e:
		result["error"] = e
	return result

_ABUSEIPDB_API_KEY = "KEY"

ABUSEIPDB_KEYS = ["isPublic", "abuseConfidenceScore", "isWhitelisted", "countryCode", "usageType", "isp", "domain", "hostnames", "totalReports", "lastReportedAt", "lastComment"]

def abuseipdb_check(ip, maxDays=180):
	result = {k:None for k in ABUSEIPDB_KEYS}
	decodedResponse = ""
	url = "https://api.abuseipdb.com/api/v2/check"
	querystring = {
		"ipAddress": f"{ip}",
		"maxAgeInDays": f"{maxDays}", 
		"verbose":True
	}
	headers = {
		"Accept": "application/json",
		"Key": _ABUSEIPDB_API_KEY
	}

	try:
		response = requests.request(method="GET", url=url, headers=headers, params=querystring)
		decodedResponse = json.loads(response.text)

		if decodedResponse.get("errors", None):
			status = decodedResponse["errors"][0]['status']
			result["error"] = status
		
		data = decodedResponse.get("data")
		if data:
			result = {k:data.get(k, result[k]) for k in ABUSEIPDB_KEYS}
			result["lastComment"] = data.get("reports", "")[0].get("comment", "")
	except Exception as e:
		result["error"] = e

	return result

_VIRUSTOTAL_API_KEY = "KEY"

def virustotal_check(collectionName, objectId):
	'''collectionName can be: "files", "ip_addresses", "urls", "domains"'''

	result = dict()

	url = f"https://www.virustotal.com/api/v3/{collectionName}/{objectId}"
	headers = {"x-apikey": _VIRUSTOTAL_API_KEY}

	response = requests.request(method="GET", url=url, headers=headers)

	decodedResponse = json.loads(response.text)

	if decodedResponse.get("error"):
		# result["error"] = response.status_code
		result["error"] = decodedResponse.get("error").get("code")
		return result
	
	stats = decodedResponse.get("data").get("attributes").get("last_analysis_stats")

	total_score = stats['malicious'] + stats['suspicious'] + stats['harmless'] + stats['undetected'] + stats['timeout']
	malicious_score = stats['malicious'] + stats['suspicious']
	percentage_score = round((malicious_score / total_score) * 100)

	result["virustotal_score"] = percentage_score

	if collectionName == "files":
		result["sha256"] = decodedResponse.get("data").get("attributes").get("sha256")
		result["name"] = decodedResponse.get("data").get("attributes").get("meaningful_name")
	
	return result

def phishtank_check(url:str):
	'''Try searching the url with http:// and https:// too.'''

	result = dict()

	request_url = "https://checkurl.phishtank.com/checkurl/"

	headers = {
	'User-Agent': 'phishtank/username'
	}

	params = {
		# "url" : url,
		"url" : requests.utils.quote(url, safe=''),
		"format" : "json",
		# "app_key" : ""
	}

	try:
		response = requests.post(url=request_url, data=params)
	except Exception as e:
		result["error"] = e
	
	decodedResponse = json.loads(response.text)

	if decodedResponse and decodedResponse["results"]:
		result = {k : decodedResponse["results"].get(k, "") for k in ["in_database", "verified", "verified_at", "valid"]}

	return result

regex_ip = r'\b((?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]))\b'
regex_url = r'^(?:https?:\/\/)?([\w-]*[a-z]+[\w-]*(?:\.[\w-]*[a-z]+[\w-]*)+)'
regex_hash = r'\b([a-z-A-Z0-9]{32,128})\b'

def get_type(target:str):
	result = dict(value='', type='', subtype='', virustotal_type='')

	match = re.search(regex_ip, target)
	if match:
		result['value'] = match.group()
		result['type'] = 'ip'
		result['subtype'] = 'ipv4'
		result['virustotal_type'] = 'ip_addresses'
		return result

	match = re.search(regex_url, target)
	if match:
		result['value'] = match.group()
		result['type'] = 'url'
		result['virustotal_type'] = 'urls'
		if re.search(match.group() + '\/.+', target):
			result['subtype'] = 'url'
			result['value'] = re.search(match.group() + '\/.+', target).group()
		else:
			result['subtype'] = 'domain'
			result['virustotal_type'] = 'domains'
		return result
	
	match = re.search(regex_hash, target)
	if match:
		result['value'] = match.group()
		result['type'] = 'hash'
		result['virustotal_type'] = 'files'
		hash_len = len(match.group())
		if hash_len == 32:
			result['subtype'] = 'md5'
		if hash_len == 40:
			result['subtype'] = 'sha1'
		if hash_len == 64:
			result['subtype'] = 'sha256'
		return result
	
	return None

