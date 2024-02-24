import threading
import time
import msvcrt # Only available on Windows. The keyboard module is a cross-platform alternative.

_running = True
_running_task = None

# def task():
# 	print(time.ctime())
# 	print(f"n of threads: {threading.active_count()}")
# 	time.sleep(5)
# 	print("task ended.")

def _check_interrupt():
	global _running
	global _running_task
	while _running:
		input_char = msvcrt.getwch() # Get the next keyboard input (without enter).
		if input_char == 'q': 
			print('\nExiting program...')
			_running = False
			if _running_task:
				_running_task.cancel()

def infinite_timer_loop(timer_interval:float, task:callable, task_args:tuple):
	global _running
	global _running_task
	print('(Press q to quit program.)\n')
	try:
		task(*task_args)

		checking_task = threading.Thread(target=_check_interrupt, daemon=True)
		checking_task.start()
		
		while _running:
			_running_task = threading.Timer(timer_interval, task, args=task_args)
			_running_task.daemon=True
			print(time.ctime()) # Print starting time.
			_running_task.start()
			_running_task.join() # Wait for the task to finish.
			print()
			time.sleep(1)
		print('\nProgram stopped.')
	except KeyboardInterrupt:
		print("\nProgram interrupted.")

# def main():
# 	infinite_timer_loop()

# if __name__ == '__main__':
# 	main()
