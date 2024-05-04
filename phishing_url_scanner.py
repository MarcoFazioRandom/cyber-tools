import sys
import re
import urllib.parse
import base64
import termcolor

url = ''

# Test
# url = r"http://www.test.com/redirect%20%20%20%20=www.mal.ru/user1=name@mail.com/?aGlkZGVuMTIzNA==/d2hhdD1oZWxsb0B3b3JsZC51cw==$"

regex_domain_in_url = r"(?:^|\/|=)((?:[0-9A-Za-z](?:-?[0-9A-Za-z]){1,62})(?:\.[0-9A-Za-z](?:-?[0-9A-Za-z]){1,62})+)(?=\/|$)"
regex_email = r'[\w\-\.]+@[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+'

def deobfuscate(url:str):
	final_url = url
	final_url = re.sub(r'hxxp://', r'http://', final_url, flags=re.IGNORECASE)
	final_url = re.sub(r'hxxps://', r'https://', final_url, flags=re.IGNORECASE)
	final_url = final_url.replace('[', '')
	final_url = final_url.replace(']', '')
	return final_url

def obfuscate(url:str):
	final_url = url
	final_url = final_url.replace(".", "[.]")
	final_url = final_url.replace("@", "[@]")
	final_url = final_url.replace(":", "[:]")
	return final_url

def replace_emails(dummy_email:str, url_data:dict):
	new_url = url_data['deobfuscated']

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
	result = {}

	result['original'] = url

	result['encoded'] = urllib.parse.quote(url, safe='')

	result['deobfuscated'] = deobfuscate(url)

	result['obfuscated'] = obfuscate(url)

	result['decoded'] = urllib.parse.unquote(result['deobfuscated'])

	result['base64_strings'] = list()
	base64Strings = find_encoded_substrings(result['deobfuscated'])
	for s in base64Strings:
		result['base64_strings'].append(s['encoded_string'])

	result['base64_strings_decoded'] = list()
	for s in base64Strings:
		result['base64_strings_decoded'].append(s['decoded_string'])

	result['domains'] = list()
	found_domain = re.findall(regex_domain_in_url, result['deobfuscated'])
	result['domains'].extend(found_domain)

	for s in result['base64_strings_decoded']:
		found_domain = re.findall(regex_domain_in_url, s)
		result['domains'].extend(found_domain)

	result['emails'] = list()
	result['emails'].extend(re.findall(regex_email, result['deobfuscated']))
	for s in result['base64_strings_decoded']:
		result['emails'].extend(re.findall(regex_email, s))

	result['url_dummy_email'] = replace_emails("user.example@google.com", result)
	result['url_dummy_email'] = obfuscate(result['url_dummy_email'] )
	
	return result

def print_colored_url(url_data:dict):
	'''
	Print the url with the domains and the email found colored
	'''

	colored_url = url_data['deobfuscated']

	for s in url_data['base64_strings']:
		splitted = colored_url.split(s)
		colored_url = termcolor.colored(s, attrs=['underline']).join(splitted)
	
	for s in url_data['domains']:
		splitted = colored_url.split(s)
		colored_url = termcolor.colored(s, color='cyan').join(splitted)
	
	for s in url_data['emails']:
		splitted = colored_url.split(s)
		colored_url = termcolor.colored(s, color='red').join(splitted)
	
	# Color in red the strings containing emails.
	for i in range(0, len(url_data['base64_strings_decoded'])):
		s_decoded = url_data['base64_strings_decoded'][i]
		if "@" in s_decoded:
			s_encoded = url_data['base64_strings'][i]
			splitted = colored_url.split(s_encoded)
			colored_url = termcolor.colored(s_encoded, color='red').join(splitted)
	
	print(obfuscate(colored_url))
	
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

	print()
	print_colored_url(url_data)
	print()

	# print(json.dumps(url_data, default=str, indent=2))

	print(termcolor.colored(f"- decoded : \n{obfuscate(url_data['decoded'])}", color='white'))
	print(termcolor.colored(f"- domains : \n{str(url_data['domains'])}", color='cyan'))
	print(termcolor.colored(f"- base64 strings : \n{str(url_data['base64_strings'])}", color='green'))
	print(termcolor.colored(f"- base64 strings decoded : \n{str(url_data['base64_strings_decoded'])}", color='green'))
	print(termcolor.colored(f"- emails : \n{str(url_data['emails'])}", color='red'))
	print(termcolor.colored(f"- url with dummy email : \n{str(url_data['url_dummy_email'])}", color='white'))

if __name__ == '__main__':
	main()

