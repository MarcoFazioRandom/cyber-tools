# from time import strftime
import whois
import shodan
import os
import ports_scanner
import socket

targets = ['www.dev2qa.com', 'blog.csdn.net', '8.8.8.8', '212.165.76.53', 'www.google.it', '78.40.70.217']
common_ports = [21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 194, 443, 445, 1433, 3306, 3389, 5632, 5900, 8080, 8443, 25565]
SHODAN_API_KEY = 'KEY'

def ping(target):
	return not os.system(f'ping {target} -n 1 > NUL')
	# stram = os.popen(f"ping {target} -n 1")
	# output = stram.read()
	# return output

# Shodan
def shodan_scan(ip):
	result = {'matches':0}
	api = shodan.Shodan(SHODAN_API_KEY)
	try:
		result['matches'] = api.count(ip)['total']
		host = api.host(ip)
		result['Organization'] = host.get('org')
		result['Hostnames'] = host.get('hostnames')
		result['Domains'] = host.get('domains')
		result['Country'] = host.get('country_name')
		result['City'] = host.get('city')
		result['Operating_System'] = host.get('os')
		result['ISP'] = host.get('isp')
		result['ASN'] = host.get('asn')
		return result
	except shodan.APIError as e:
		return result

# Whois
def whois_scan(target):
	result = dict()
	w = whois.whois(target)
	result['domain_name'] = w.get('domain_name')
	result['registrar'] = w.get('registrar')
	result['whois_server'] = w.get('whois_server')
	result['country'] = w.get('country')
	result['state'] = w.get('state')
	result['creation_date'] = w.get('creation_date').strftime('%Y-%m-%d') if w.get('creation_date') else ''
	result['updated_date'] = w.get('updated_date').strftime('%Y-%m-%d') if w.get('creation_date') else ''
	result['expiration_date'] = w.get('expiration_date').strftime('%Y-%m-%d') if w.get('creation_date') else ''
	return result

def ports_scan(ip):
	return ports_scanner.port_scan(ip, common_ports)

def hunt(target):
	result = dict()
	try:
		host_ip = socket.gethostbyname(target)
	except:
		host_ip = target
	result['host_ip'] = host_ip if host_ip != target else ''
	result['ping'] = True if ping(target) else None
	result.update(whois_scan(target))
	result.update(shodan_scan(host_ip))
	result['open_ports'] = ports_scan(target)
	return result

# r = hunt('www.google.com')
# r = hunt('142.250.186.132')
# r = hunt('212.165.76.53')
# is_empty = not any(r.values())
# print(is_empty, '\n', r)
