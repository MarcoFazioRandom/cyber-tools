import re

# regex_allowed_chars_in_url = r'[0-9a-zA-Z\-_.~!*\'\(\);:@&=+$,\/?%#]+'
regex_url = r'^https?:\/\/[0-9a-zA-Z\-_.~!*\'\(\);:@&=+$,\/?%#]+'
regex_domain = r"(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}"
regex_ip = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
regex_ipv6 = r'(?:[0-9a-fA-F]{0,4}:){1,6}(?:(?:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:?)|(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))'
regex_hash = r'[a-z-A-Z0-9]{32,128}'
regex_email = r'[\w\-\.]+@[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+'

def get_type(target:str):
	result = {"type":"", "subtype":""}

	match = re.match(regex_ip, target)
	if match and match.group() == target:
		result["type"] = "ip"
		result["subtype"] = "ipv4"
		return result

	match = re.match(regex_ipv6, target)
	if match and match.group() == target:
		result["type"] = "ip"
		result["subtype"] = "ipv6"
		return result
	
	match = re.match(regex_hash, target)
	if match and match.group() == target:
		result["type"] = "hash"
		hash_len = len(match.group())
		if hash_len == 32:
			result['subtype'] = 'md5'
		if hash_len == 40:
			result['subtype'] = 'sha1'
		if hash_len == 64:
			result['subtype'] = 'sha256'
		return result

	match = re.match(regex_email, target)
	if match and match.group() == target:
		result["type"] = "email"
		return result

	match = re.match(regex_domain, target)
	if match and match.group() == target:
		result["type"] = "domain"
		return result
	
	match = re.match(regex_url, target)
	if match and match.group() == target:
		result["type"] = "url"
		return result
	
	return result

