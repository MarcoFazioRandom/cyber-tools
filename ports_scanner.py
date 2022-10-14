# SuperFastPython.com
# scan a range of port numbers on a host concurrently
from socket import AF_INET
from socket import SOCK_STREAM
from socket import socket
from concurrent.futures import ThreadPoolExecutor
 
# returns True if a connection can be made, False otherwise
def test_port_number(host, port):
    # create and configure the socket
    with socket(AF_INET, SOCK_STREAM) as sock:
        # set a timeout of a few seconds
        sock.settimeout(5)
        # connecting may fail
        try:
            # attempt to connect
            sock.connect((host, port))
            # a successful connection was made
            return True
        except:
            # ignore the failure
            return False
 
# scan port numbers on a host
def port_scan(host, ports):
    # print(f'Scanning {host}...')
    result = ''
    # create the thread pool
    with ThreadPoolExecutor(len(ports)) as executor:
        # dispatch all tasks
        results = executor.map(test_port_number, [host]*len(ports), ports)
        # report results in order
        for port,is_open in zip(ports,results):
            if is_open:
                # print(f'> {host}:{port} open')
                if (result != ''):
                    result += ', '
                result += f'{port}'
    return result
 
# define host and port numbers to scan
# HOST = '212.165.78.8'
# PORTS = range(1024)
# test the ports
# print(port_scan(HOST, PORTS))