import sys
import time
import threading
from socket import socket
from socket import SOCK_STREAM
from socket import AF_INET
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 194, 443, 445, 1433, 3306, 3389, 5632, 5900, 8080, 8443, 25565]

def test_port(ip:str, port:str):
	with socket(AF_INET, SOCK_STREAM) as sock:
		sock.settimeout(5)
		try:
			sock.connect((ip, port))
			return True
		except:
			return False

_loading = False

def test_ports(ip:str, ports:list=COMMON_PORTS, with_rotating_wheel=False):
	result = ''
	global _loading
	if with_rotating_wheel:
		_loading = True
		wheel = threading.Thread(target=rotating_wheel, daemon=True)
		wheel.start()
	with ThreadPoolExecutor(len(ports)) as executor:
		results = executor.map(test_port, [ip]*len(ports), ports)
		for port,is_open in zip(ports,results):
			if is_open:
				result += f"{port} "
	if with_rotating_wheel:
		_loading = False
		print('\r', sep='', end='', flush=True)
	return result

def rotating_wheel():
	cursor = r"-\|/"
	count = 0
	while _loading:
		to_print = cursor[count%len(cursor)]
		print('\r', to_print, sep='', end='', flush=True)
		time.sleep(0.2)
		count += 1

def main():
	ip = ''
	
	ports = COMMON_PORTS

	if len(sys.argv) >= 2:
		ip = sys.argv[1]

	if len(sys.argv) >= 3:
		ports = [i for i in range(int(sys.argv[2]))]

	print(f"ip: {ip} \nn of ports:{len(ports)}")

	open_ports = test_ports(ip, ports, with_rotating_wheel=True)

	print(open_ports)

if __name__ == '__main__':
	main()
