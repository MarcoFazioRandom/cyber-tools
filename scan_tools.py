from datetime import datetime
import whois
import shodan
import os
import requests
import json

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

SHODAN_KEYS = ["matches", "org", "hostnames", "domains", "C", "country_name", "city", "os", "isp", "last_update"]

def shodan_check(ip, keys=None):
	result = {k:None for k in SHODAN_KEYS}
	api = shodan.Shodan(_SHODAN_API_KEY)
	try:
		result["matches"] = api.count(ip).get("total", 0)
		if result["matches"] == 0:
			return result
		host = api.host(ip)
		if keys:
			result = {k:host.get(k, result[k]) for k in keys}
		else:
			result.update(host)
	except:
		pass
	return result

WHOIS_KEYS = ["domain_name", "registrar", "whois_server", "referral_url", "creation_date", "updated_date", "expiration_date", "name_servers", "emails", "org", "country"]

# Whois
def whois_check(target):
	result = {k:None for k in WHOIS_KEYS}
	try:
		w = whois.whois(target)
		result = {k:w.get(k, result[k]) for k in WHOIS_KEYS}
	except:
		pass
	return result

_ABUSEIPDB_API_KEY = "KEY"

ABUSEIPDB_KEYS = ["isPublic", "abuseConfidenceScore", "isWhitelisted", "countryCode", "usageType", "isp", "domain", "hostnames", "totalReports", "lastReportedAt"]

def abuseipdb_check(ip, maxDays=180):
	result = {k:None for k in ABUSEIPDB_KEYS}
	decodedResponse = ""
	url = "https://api.abuseipdb.com/api/v2/check"
	querystring = {
		"ipAddress": f"{ip}",
		"maxAgeInDays": f"{maxDays}", 
		# "verbose":True
	}
	headers = {
		"Accept": "application/json",
		"Key": _ABUSEIPDB_API_KEY
	}

	try:
		response = requests.request(method="GET", url=url, headers=headers, params=querystring)
		decodedResponse = json.loads(response.text)

		if decodedResponse["errors"]:
			status = decodedResponse["errors"][0]['status']
			return status
		
		data = decodedResponse.get("data")
		if data:
			result = {k:data.get(k, result[k]) for k in ABUSEIPDB_KEYS}
	except:
		return "request error"

	return result

_VIRUSTOTAL_API_KEY = "KEY"

# collectionName can be: files, ip_addresses, urls, domains
def virustotal_check(collectionName, objectId):
	url = f"https://www.virustotal.com/api/v3/X{collectionName}/{objectId}"
	headers = {"x-apikey": _VIRUSTOTAL_API_KEY}
	response = requests.request(method="GET", url=url, headers=headers)
	decodedResponse = json.loads(response.text)
	if decodedResponse.get("error"):
		return {"error" : decodedResponse.get("error").get("code")}
	
	result = {}
	
	stats = decodedResponse.get("data").get("attributes").get("last_analysis_stats")

	total_score = stats['malicious'] + stats['suspicious'] + stats['harmless'] + stats['undetected'] + stats['timeout']
	malicious_score = stats['malicious'] + stats['suspicious']
	percentage_score = round((malicious_score / total_score) * 100)

	result["vt_score"] = percentage_score

	if collectionName == "files":
		result["sha256"] = decodedResponse.get("data").get("attributes").get("sha256")
		result["name"] = decodedResponse.get("data").get("attributes").get("meaningful_name")
	
	return result

