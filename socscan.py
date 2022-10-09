import whois
import shodan
import os

def ping(target):
	return not os.system('ping %s -n 1 > NUL' % (target,))

# Shodan 
def shodan_scan(ip):
	result = ''
	SHODAN_API_KEY = 'KEY'
	api = shodan.Shodan(SHODAN_API_KEY)
	try:
		host = api.host(ip)
		result = 'IP: {} \nOrganization: {} \nOperating System: {}'.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'))
	except shodan.APIError as e:
		# result = 'Error: {}'.format(e)
		return result
	return result

# Whois
def whois_scan(ip):
	result = ''
	w = whois.whois(ip)
	domain = w['domain_name']
	registrar = w['registrar']
	server = w['whois_server']
	if (domain != None and registrar != None and server != None):
		result = 'domain_name: {} \nregistrar: {} \nwhois_server: {}'.format(domain, registrar, server)
	return result

def rf_scan(ip):
	result = ''
	return result

def ports_scan(ip):
	result = ''
	return result

def run_full_scan(ips):
	found_result = dict()
	for ip in ips:
		print('{} scan: '.format(ip))
		ping_result = ping(ip)
		whois_result = whois_scan(ip)
		shodan_result = shodan_scan(ip)
		rf_result = rf_scan(ip)
		ports_result = ports_scan(ip)
		if (ping_result or whois_result or shodan_result or rf_result or ports_result):
			found_result[ip] = '''- Ping: {} 
	- Whois: {} 
	- Shodan: {} 
	- Recordedfuture: {} 
	- Open ports: {} '''.format(ping_result, whois_result, shodan_result, rf_result, ports_result)

	print('found {} out of {}'.format(len(found_result), len(ips)))
	for k, v in found_result.items():
		print('''{}: 
	{} 
	'''.format(k, v))

