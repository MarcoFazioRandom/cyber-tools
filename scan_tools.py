from datetime import datetime
import whois
import shodan
import os
import ports_scanner
import requests
import json

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 194, 443, 445, 1433, 3306, 3389, 5632, 5900, 8080, 8443, 25565]
SHODAN_API_KEY = "KEY"
ABUSEIPDB_KEY = "KEY"

def ping(target):
	return not os.system(f"ping {target} -n 1 > NUL")
	# stream = os.popen(f"ping {target} -n 1")
	# output = stream.read()
	# return output

shodan_keys = ["matches", "org", "hostnames", "domains", "C", "country_name", "city", "os", "isp", "last_update"]

def shodan_scan(ip):
	result = {k:None for k in shodan_keys}
	api = shodan.Shodan(SHODAN_API_KEY)
	try:
		result["matches"] = api.count(ip).get("total", 0)
		if result["matches"] == 0:
			return result
		host = api.host(ip)
		result = {k:host.get(k, result[k]) for k in shodan_keys}
	except:
		pass
	return result

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

whois_keys = ["domain_name", "registrar", "whois_server", "referral_url", "creation_date", "updated_date", "expiration_date", "name_servers", "emails", "org", "country"]

# Whois
def whois_scan(target):
	result = {k:None for k in whois_keys}
	try:
		w = whois.whois(target)
		result = {k:w.get(k, result[k]) for k in whois_keys}
	except:
		pass
	return result

def open_ports_scan(ip):
	return ports_scanner.port_scan(ip, COMMON_PORTS)

abuseipdb_keys = ["abuseConfidenceScore", "isWhitelisted", "countryCode", "usageType", "isp", "domain", "hostnames", "totalReports", "lastReportedAt"]

def abuseipdb_scan(ip):
	result = {k:None for k in abuseipdb_keys}
	url = "https://api.abuseipdb.com/api/v2/check"
	querystring = {
		"ipAddress": f"{ip}",
		"maxAgeInDays": "30"
	}
	headers = {
		"Accept": "application/json",
		"Key": ABUSEIPDB_KEY
	}
	try:
		response = requests.request(method="GET", url=url, headers=headers, params=querystring)
		decodedResponse = json.loads(response.text)
		data = decodedResponse["data"]
		result = {k:data.get(k, result[k]) for k in abuseipdb_keys}
	except:
		pass
	return result
