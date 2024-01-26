import os
import termcolor
import time
from datetime import datetime
from urllib.request import urlopen
from urllib.error import URLError
from urllib.error import HTTPError
from http import HTTPStatus
from threading import Thread
import re

try:
	os.system('color')
except:
	pass

timer_loop = 300

URLS = ['www.google.com',
		'www.twitter.com']

# get the status of a website
def get_website_status(url):
	# handle connection errors
	try:
		# open a connection to the server with a timeout
		with urlopen(url, timeout=3) as connection:
			# get the response code, e.g. 200
			code = connection.getcode()
			return code
	except HTTPError as e:
		return e.code
	except URLError as e:
		return e.reason
	except Exception as e:
		return e
 
# interpret an HTTP response code into a status
def get_status(code):
	if code == HTTPStatus.OK:
		return 'OK'
	return 'ERROR'
 
# check status of a list of websites
def check_status_urls(urls):
	for url in urls:
		# get the status for the website
		code = get_website_status(url)
		# interpret the status
		status = get_status(code)
		# report status
		print(f'{url:20s}\t{status:5s}\t{code}')

def ping(target):
	return not os.system(f"ping {target} -n 1 > NUL")

def get_domain(url):
	regex_domain = r"(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}"
	return re.search(regex_domain, url).group()

def check_website_status(urls, timer):
	while (True):
		print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
		print("URL\t\t\tPING\tstatus\tcode")
		for url in urls:

			ping_result = ping(get_domain(url))

			url = "https://" + url

			# get the status for the website
			code = get_website_status(url)

			# interpret the status
			status = get_status(code)

			ping_color = "green" if ping_result else "red"
			status_color ="green" if status=="OK" else "red"

			output = termcolor.colored(f"{url:20s}")
			output += termcolor.colored(f"\t{ping_result}", ping_color)
			output += termcolor.colored(f"\t{status:5s}\t{code}", status_color)

			print(output)
			
		print()
		time.sleep(timer)

def background_loop():
	thread = Thread(target=check_website_status, args=(URLS, timer_loop,), daemon=True)
	thread.start()
	thread.join()

def main():
	background_loop()

if __name__ == '__main__':
	main()
