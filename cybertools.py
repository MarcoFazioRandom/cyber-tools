import sys
import os
from datetime import datetime
import requests
import shodan
import json
import re
import socket
# pip install python-whois
import whois.whois as python_whois
# pip install ipwhois
from ipwhois import IPWhois
from pprint import pprint
import settings
import base64
import myregex

def get_hostname(target:str):
	return socket.getnameinfo((target, 0), 0)[0]

def ping(target):
	return not os.system(f"ping {target} -n 1 > NUL")
	# stream = os.popen(f"ping {target} -n 1")
	# output = stream.read()
	# return output

def shodan_check(ip):
	SHODAN_KEYS = ["country_code", "domains", "hostnames", "isp", "org", "os", "ports", "tags"]
	result = dict()
	try:
		api = shodan.Shodan(settings.SHODAN_API_KEY)
		host = api.host(ip)
		for k in SHODAN_KEYS:
			result[k] = host.get(k, "")
			if isinstance(result[k], list) and len(result[k]) > 1:
				result[k] = result[k][0]
		if host.get("last_update"):
			result["last_update"] = re.match(r"\d\d\d\d-\d\d?-\d\d?", host.get("last_update")).group()
	except Exception as e:
		result["error"] = e
	return result

def whois_domain(target:str):
	WHOIS_DOMAIN_KEYS = ['country', 'creation_date', 'domain_name', 'expiration_date', 'org', 'registrar', 'updated_date']
	result = dict()
	try:
		w = python_whois(target)
		for k in WHOIS_DOMAIN_KEYS:
			result[k] = w.get(k, "")
			if isinstance(result[k], list) and len(result[k]) > 1:
				result[k] = result[k][0]
			if isinstance(result[k], datetime):
				result[k] = result[k].strftime(r"%Y-%m-%d")
	except Exception as e:
		result["error"] = e
	return result

def whois_ip(target:str):
	WHOIS_IP_KEYS = ['asn_country_code', 'asn_date', 'asn_description', 'asn_registry']
	result = dict()
	try:
		result['hostname'] = get_hostname(target)
		w = IPWhois(target)
		# w = w.lookup_rdap()
		w = w.lookup_whois()
		for k in WHOIS_IP_KEYS:
			result[k] = w.get(k, "")
			if isinstance(result[k], datetime):
				result[k] = result[k].strftime(r"%Y-%m-%d")
	except Exception as e:
		result["error"] = e
	return result

def abuseipdb_check(ip, maxDays=180):
	ABUSEIPDB_KEYS = ["isPublic", "abuseConfidenceScore", "isWhitelisted", "isTor", "countryCode", "usageType", "isp", "domain", "hostnames", "totalReports", "lastReportedAt", "lastComment"]

	decodedResponse = ""
	url = "https://api.abuseipdb.com/api/v2/check"
	querystring = {
		"ipAddress": f"{ip}",
		"maxAgeInDays": f"{maxDays}", 
		"verbose":True
	}
	headers = {
		"Accept": "application/json",
		"Key": settings.ABUSEIPDB_API_KEY
	}

	result = dict()

	try:
		response = requests.request(method="GET", url=url, headers=headers, params=querystring)
		decodedResponse = json.loads(response.text)

		result["status"] = response.status_code

		if response.status_code != 200:
			return result
		
		data = decodedResponse.get("data")
		if data:
			for k in ABUSEIPDB_KEYS:
				result[k] = data.get(k, "")
				if data.get("reports"):
					result["lastComment"] = data.get("reports")[0].get("comment", "")
				if data.get("lastReportedAt"):
					result["lastReportedAt"] = re.match(r"\d\d\d\d-\d\d?-\d\d?", result["lastReportedAt"]).group()
	except Exception as e:
		result["error"] = e

	return result

def virustotal_check(target):
	# collectionName can be: "files", "ip_addresses", "urls", "domains"

	target_type = myregex.get_type(target)
	collection_name = ""

	if not target_type.get("type"):
		return None
	elif target_type["type"] == "ip":
		collection_name =  "ip_addresses"
	elif target_type["type"] == "hash":
		collection_name =  "files"
	elif target_type["type"] == "domain":
		collection_name =  "domains"
	elif target_type["type"] == "url":
		collection_name =  "urls"

	result = dict()

	if collection_name == 'urls':
		target = base64.urlsafe_b64encode(target.encode()).decode().strip("=")

	url = f"https://www.virustotal.com/api/v3/{collection_name}/{target}"
	headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

	response = requests.request(method="GET", url=url, headers=headers)

	decodedResponse = json.loads(response.text)

	result['status'] = response.status_code

	if response.status_code != 200:
		return result

	attributes = decodedResponse.get("data").get("attributes")

	stats = attributes.get("last_analysis_stats")
	malicious_score = stats["malicious"] + stats["suspicious"]
	benign_score = stats["harmless"] + stats["undetected"]
	result["malicious_score"] =  round((malicious_score / (malicious_score + benign_score)) * 100)

	result["community_reputation"] = attributes["reputation"]

	tags = attributes.get('tags')
	result['tag'] = tags[0] if tags else None

	if attributes.get('last_analysis_date'):
		result['last_analysis_date'] = datetime.fromtimestamp(attributes.get('last_analysis_date')).strftime(r"%Y-%m-%d")

	if collection_name == 'ip_addresses':
		pass
	elif collection_name == 'files':
		for k in ["md5", "meaningful_name", "sha1", "sha256"]:
			result[k] = attributes.get(k, "")
		result["threat"] = attributes.get('popular_threat_classification', {}).get('suggested_threat_label')
		result['identification'] = attributes.get('magic')
		result['size_megabytes'] = round(attributes.get('size', 0) / 1048576, 2)
	elif collection_name == 'domains':
		pass
	elif collection_name == 'urls':
		threat_names = attributes.get('threat_names')
		result['threat_name'] = threat_names[0] if threat_names else None

	return result

def deobfuscate(url:str):
	final_url = url
	final_url = re.sub(r'hxxp://', r'http://', final_url, flags=re.IGNORECASE)
	final_url = re.sub(r'hxxps://', r'https://', final_url, flags=re.IGNORECASE)
	final_url = final_url.replace('[', '')
	final_url = final_url.replace(']', '')
	return final_url

def obfuscate(url:str):
	final_url = deobfuscate(url)
	final_url = final_url.replace(".", "[.]")
	final_url = final_url.replace("@", "[@]")
	final_url = final_url.replace(":", "[:]")
	return final_url

def main():
	if len(sys.argv) == 3:
		try:
			func = globals()[sys.argv[1]]
			pprint(func(sys.argv[2]))
		finally:
			pass

if __name__ == '__main__':
	main()
