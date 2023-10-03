#!/bin/env python3

import os, re

rgx = r'^(\S+)\s+(\d+)/tcp'

#11 systat
#13 daytime
#15 netstat
#17 qotd
#18 msp
#19 loaden
#20 ftp-data
#79 finger

COMMENT = '# For 42 evaluation use'

ports = {
        '11': 'systat',
        '13': 'daytime', 
        '15': 'netstat', 
        '17': 'qotd', 
        '18': 'msp', 
        '19': 'loaden', 
        '20': 'ftp-data', 
        '67': 'dhcps',
        '79': 'finger', 
        }
array = None

if __name__ == "__main__":
    if (os.getuid() != 0):
        print("Error: Must be run as sudo user")
        exit(1)
    with open("/etc/services", "r") as file:
        array = file.read().split('\n')
    with open("/etc/services", "w") as file:
        i = 0
        for line in array:
            match = re.search(rgx, line)
            if match:
                serv = match.group(1)
                port = match.group(2)
                if port in ports:
                    continue
            print(line, file=file)
        print(f'\n{COMMENT}', file=file)
        for port, serv in ports.items():
            port += '/tcp'
            print(f'{serv:16s}{port:32s}', file=file)
