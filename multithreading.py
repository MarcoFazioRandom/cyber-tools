import threading
import scan_tools
import time

def task(x):
	print(f'hello {x}')
	time.sleep(2)
	print(f'world {x}')

def start_multithreading():
	threads = []
	for i in range(10):
		print(i)
		threads.append(threading.Thread(target=task, args=(i)))
	for thread in threads:
		thread.start()
	for thread in threads:
		thread.join()
	# Check if threads have finished 
	while True:
		for thread in threads:
			if thread.is_alive():
				break
		break
	print('finished')

start_multithreading()

