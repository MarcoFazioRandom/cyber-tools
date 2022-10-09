# SuperFastPython.com
# example of thread-safe writing to a file with a dedicated writer thread
from random import random
from threading import Thread
from queue import Queue
import os

# dedicated file writing task
def file_writer(filepath, queue):
	complete_filepath = os.path.dirname(os.path.abspath(__file__)) + '\\' + filepath
	# open the file
	with open(complete_filepath, 'w') as file:
		# run until the event is set
		while True:
			# get a line of text from the queue
			line = queue.get()
			# check if we are done
			if line is None:
				# exit the loop
				break
			# write it to file
			file.write(line)
			# flush the buffer
			file.flush()
			# mark the unit of work complete
			queue.task_done()
	# mark the exit signal as processed, after the file was closed
	queue.task_done()

# task for worker threads


def task(number, queue):
	# task loop
	for i in range(1000):
		# generate random number between 0 and 1
		value = random()
		# put the result in the queue
		queue.put(f'Thread {number} got {value}.\n')


# create the shared queue
queue = Queue()
# defile the shared file path
filepath = 'output.txt'
# create and start the file writer thread
writer_thread = Thread(target=file_writer, args=(filepath, queue), daemon=True)
writer_thread.start()
# configure worker threads
threads = [Thread(target=task, args=(i, queue)) for i in range(1000)]
# start threads
for thread in threads:
	thread.start()
# wait for threads to finish
for thread in threads:
	thread.join()
# signal the file writer thread that we are done
queue.put(None)
# wait for all tasks in the queue to be processed
queue.join()