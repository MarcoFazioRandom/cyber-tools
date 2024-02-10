import os
import time
from datetime import datetime
from threading import Thread
import check_host

SECONDS_LOOP = 300

CHECKTYPE = "http"

URLS = ['https://www.google.com',
		'https://www.bing.com']

def infinite_loop():
	while (True):
		print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
		for url in URLS:
			print(url)
			check_host.check_host(url, CHECKTYPE)
			print()
			
		print()
		time.sleep(SECONDS_LOOP)

def background_loop():
	thread = Thread(target=infinite_loop, args=(), daemon=True)
	thread.start()
	thread.join()

def main():
	background_loop()

if __name__ == '__main__':
	main()
