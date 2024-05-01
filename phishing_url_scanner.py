import sys
import re
import urllib.parse
import json
import base64
import termcolor
import myregex
import cybertools

url = ''
# url = r"www.google"

def replace_emails(dummy_email:str, url_data:dict):
	new_url = url_data['original']

	if len(url_data['emails']) == 0:
		return new_url

	for email in url_data['emails']:
		new_url = new_url.replace(email, dummy_email)

	for i in range(len(url_data['base64_strings'])):
		new_string_decoded = url_data['base64_strings_decoded'][i]
		for email in url_data['emails']:
			new_string_decoded = new_string_decoded.replace(email, dummy_email)
		new_string_encoded = base64.b64encode(new_string_decoded.encode('utf-8')).decode('utf-8')
		new_url = new_url.replace(url_data['base64_strings'][i], new_string_encoded)
	
	return new_url

def analyze(url:str):
	keys = ['original', 'obfuscated', 'deobfuscated', 'encoded', 'decoded', 'domains', 'ips', 'base64_strings', 'base64_strings_decoded', 'emails', 'url_with_dummy_user']

	result = {k:'' for k in keys}

	result['original'] = url

	result['encoded'] = urllib.parse.quote(url, safe='')

	result['decoded'] = urllib.parse.unquote(url)

	result['obfuscated'] = cybertools.obfuscate(url)

	result['deobfuscated'] = cybertools.deobfuscate(url)

	result['base64_strings'] = list()
	base64Strings = find_encoded_substrings(url)
	for s in base64Strings:
		result['base64_strings'].append(s['encoded_string'])

	result['base64_strings_decoded'] = list()
	for s in base64Strings:
		result['base64_strings_decoded'].append(s['decoded_string'])

	result['domains'] = list()
	found_domain = re.findall(myregex.regex_domain_restrictive, result['deobfuscated'])
	result['domains'].extend(found_domain)

	for s in result['base64_strings_decoded']:
		found_domain = re.findall(myregex.regex_domain_restrictive, result['deobfuscated'])
		result['domains'].extend(found_domain)

	result['ips'] = list()
	result['ips'].extend(re.findall(myregex.regex_ip, result['deobfuscated']))
	for s in result['base64_strings_decoded']:
		result['ips'].extend(re.findall(myregex.regex_ip, s))

	result['emails'] = list()
	result['emails'].extend(re.findall(myregex.regex_email, result['deobfuscated']))
	for s in result['base64_strings_decoded']:
		result['emails'].extend(re.findall(myregex.regex_email, s))

	result['url_with_dummy_user'] = replace_emails("user.example@google.com", result)
	
	return result

def print_colored_url(url_data:dict):
	'''
	Print the url with the domains and the email found colored
	'''

	colored_url = url_data['original']

	for s in url_data['base64_strings']:
		splitted = colored_url.split(s)
		colored_url = termcolor.colored(s, attrs=['underline']).join(splitted)
	
	for s in url_data['domains']:
		splitted = colored_url.split(s)
		colored_url = termcolor.colored(s, color='cyan').join(splitted)
	
	for s in url_data['ips']:
		splitted = colored_url.split(s)
		colored_url = termcolor.colored(s, color='yellow').join(splitted)
	
	for s in url_data['emails']:
		splitted = colored_url.split(s)
		colored_url = termcolor.colored(s, color='red').join(splitted)
	
	for i in range(0, len(url_data['base64_strings_decoded'])):
		s_decoded = url_data['base64_strings_decoded'][i]
		if "@" in s_decoded:
			s_encoded = url_data['base64_strings'][i]
			splitted = colored_url.split(s_encoded)
			colored_url = termcolor.colored(s_encoded, color='red').join(splitted)
	
	print(colored_url)
	
	return colored_url

def find_longest_encoded_string(input:str):
	'''Return the index of the end character and the decoded string'''
	
	for i in range(len(input), 3, -1):
		substring = input[0 : i]
		
		try:
			decoded_string = base64.b64decode(substring, validate=True).decode('utf-8')
		except:
			continue
		
		if decoded_string and decoded_string.isprintable():
			return dict(end_index = i, decoded_string = decoded_string)
		
	return None

def find_encoded_substrings(input:str, min_length=8):
	'''Return a list where each element is a dictionary of these elements: 'start_index' (where the substring starts), 'end_index' (where the substring ends), 'encoded_string' and 'decoded_string'. '''

	if len(input) < 4:
		return list()
	
	result = list()

	i = 0
	while i <= len(input) - 4:
		substring = input[i : len(input)]
		max_substring = find_longest_encoded_string(substring)
		if max_substring and len(max_substring['decoded_string']) >= min_length:
			result.append(dict(start_index = i, end_index = i + max_substring['end_index'], encoded_string = substring[:max_substring['end_index']], decoded_string = max_substring['decoded_string']))
			i += max_substring['end_index']
		else:
			i += 1
	
	return result

def main():
	global url
	if len(sys.argv) == 1:
		if not url:
			url = input("insert url to decode: ")
	elif len(sys.argv) == 2:
		url = sys.argv[1]
	else:
		print(termcolor.colored("Invalid arguments!", "red"))
		return
	
	url_data = analyze(url)

	print_colored_url(url_data)
	print()

	# print(json.dumps(url_data, default=str, indent=2))

	print(termcolor.colored(f"- decoded : \n{url_data['decoded']}", color='white'))
	print(termcolor.colored(f"- obfuscated : \n{url_data['obfuscated']}", color='white'))
	# print(termcolor.colored(f"- deobfuscated : \n{url_data['deobfuscated']}", color='white'))
	print(termcolor.colored(f"- domains : \n{str(url_data['domains'])}", color='cyan'))
	print(termcolor.colored(f"- ips : \n{str(url_data['ips'])}", color='yellow'))
	print(termcolor.colored(f"- base64_strings : \n{str(url_data['base64_strings'])}", color='green'))
	print(termcolor.colored(f"- base64_strings_decoded : \n{str(url_data['base64_strings_decoded'])}", color='green'))
	print(termcolor.colored(f"- emails : \n{str(url_data['emails'])}", color='red'))
	print(termcolor.colored(f"- url_with_dummy_user : \n{str(url_data['url_with_dummy_user'])}", color='white'))

if __name__ == '__main__':
	main()

