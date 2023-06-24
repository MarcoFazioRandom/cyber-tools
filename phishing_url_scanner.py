import re
import urllib.parse
import json
import base64
import termcolor

url = r"https://www.google.com/"

base64StringRegex = r"[?\/=]([+a-zA-Z0-9]{10,}={0,2})\/?$"
emailRegex = r"[\w-]+(?:\.\w+)?@\w+\.[a-z]{2,3}"
domainRegex = r"\/([\w-]*[a-z]+[\w-]*(?:\.[\w-]*[a-z]+[\w-]*)+)\/"
ipRegex = r"https?:\/\/((?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]))\b"

#s = input("Link to edit:\n")

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

def analyze(url:str):
	keys = ['obfuscated', 'deobfuscated', 'encoded', 'decoded', 'domains', 'ips', 'base64_strings', 'base64_strings_decoded', 'emails', 'url_with_dummy_user']

	result = {k:'' for k in keys}

	result['encoded'] = urllib.parse.quote(url, safe='')

	result['decoded'] = urllib.parse.unquote(url)

	result['obfuscated'] = obfuscate(result['decoded'])

	result['deobfuscated'] = deobfuscate(result['decoded'])

	result['base64_strings'] = list()
	base64Strings = find_encoded_substrings(result['deobfuscated'])
	for s in base64Strings:
		result['base64_strings'].append(s['encoded_string'])

	result['base64_strings_decoded'] = list()
	for s in base64Strings:
		result['base64_strings_decoded'].append(s['decoded_string'])

	result['domains'] = list()
	result['domains'].extend(re.findall(domainRegex, result['deobfuscated']))
	for s in result['base64_strings_decoded']:
		result['domains'].extend(re.findall(domainRegex, s))

	result['ips'] = list()
	result['ips'].extend(re.findall(ipRegex, result['deobfuscated']))
	for s in result['base64_strings_decoded']:
		result['ips'].extend(re.findall(ipRegex, s))

	result['emails'] = list()
	result['emails'].extend(re.findall(emailRegex, result['deobfuscated']))
	for s in result['base64_strings_decoded']:
		result['emails'].extend(re.findall(emailRegex, s))

	dummy_username = 'user.example@google.com'

	result['url_with_dummy_user'] = url

	for email in result['emails']:
		result['url_with_dummy_user'] = result['url_with_dummy_user'].replace(email, dummy_username)

	for i in range(len(result['base64_strings'])):
		new_string_decoded = result['base64_strings_decoded'][i]
		for email in result['emails']:
			new_string_decoded = new_string_decoded.replace(email, dummy_username)
		new_string_encoded = base64.b64encode(new_string_decoded.encode('utf-8')).decode('utf-8')
		result['url_with_dummy_user'] = result['url_with_dummy_user'].replace(result['base64_strings'][i], new_string_encoded)
	
	if result['url_with_dummy_user'] == url:
		result['url_with_dummy_user'] = ''
	
	return result

def print_colored_url(url_data:dict):
	'''
	Print the url with the domains and the email found colored
	'''

	colored_url = url_data['deobfuscated']

	for s in url_data['base64_strings']:
		splitted = colored_url.split(s)
		colored_url = termcolor.colored(s, color='green', attrs=['underline']).join(splitted)
	
	for s in url_data['domains']:
		splitted = colored_url.split(s)
		colored_url = termcolor.colored(s, color='cyan').join(splitted)
	
	for s in url_data['ips']:
		splitted = colored_url.split(s)
		colored_url = termcolor.colored(s, color='yellow').join(splitted)
	
	for s in url_data['emails']:
		splitted = colored_url.split(s)
		colored_url = termcolor.colored(s, color='red').join(splitted)
	
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
			return dict(end_index = i-1, decoded_string = decoded_string)
		
	return None

def find_encoded_substrings(input:str, min_length=10):
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
	url_data = analyze(url)

	print_colored_url(url_data)

	print(json.dumps(url_data, default=str, indent=2))

if __name__ == '__main__':
	main()
