#!/usr/bin/python3
# https://github.com/dievus/threader3000

import os
import signal
import socket
import subprocess
import sys
import threading
import time
from queue import Queue


def scan_network(ip, portlist=[22, 80, 443, 5985, 5986], threadcount=range(4)):
    # for now use only for one ip at a time
    final_result = {ip: []}
    socket.setdefaulttimeout(0.30)
    print_lock = threading.Lock()

    def portscan(t_ip, port):
        # not thread safe to have multiple ip
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            portx = s.connect((t_ip, port))
            with print_lock:
                # print("Port {} {} is open".format(t_ip, port))
                final_result[ip].append(port)
            portx.close()

        except (ConnectionRefusedError, AttributeError, OSError):
            pass

    def threader():
        while True:
            iip, iport = q.get()
            portscan(iip, iport)
            q.task_done()

    q = Queue()

    for x in threadcount:
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    for portno in portlist:
        q.put((ip, portno))

    q.join()
    return final_result


if __name__ == '__main__':
    try:
        res = scan_network('10.128.7.80', [22, 80, 443, 5985, 5986])
        print(res)
    except KeyboardInterrupt:
        print("\nGoodbye!")
        quit()
