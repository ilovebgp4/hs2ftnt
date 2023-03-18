#!/usr/local/bin/python3
# -*- coding: UTF-8 -*-
# @Time    : 2022/08/18
# @Author  : Chen Jiang
# @Mail    : chenjiang@microshield.com.cn

import re
import ipaddress

def rmnoise():
    with open('h1.txt', 'r') as file:
        text = file.read()
        text = re.sub(r'\[[^\]]*\]', '', text)
    with open('h2.txt', 'w') as file:
        file.write(text)

def is_address(ip_address):
    """Returns True if the given string is a valid IP address, False otherwise."""
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(pattern, ip_address):
        octets = ip_address.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True
    return False

def is_prefix(prefix):
    try:
        ipaddress.IPv4Network(prefix)
        return True
    except ipaddress.AddressValueError:
        return False

def getservice():
    filename = 'h2.txt'
    start_marker = 'service'
    end_marker = 'exit'
    capturing = False
    captured_lines = []

    with open(filename,'r',encoding='utf-8') as file:
        for line in file:
            if line.startswith(start_marker):
                capturing = True
                captured_lines.append(line.strip())
            elif line.startswith(end_marker) and capturing:
                capturing = False
                captured_lines.append(line.strip())
                ServiceTrans(captured_lines)     
                captured_lines = []       
            elif capturing:
                captured_lines.append(line.strip())
            

def ServiceTrans(captured_lines):
    num = len(captured_lines)
    protnum = 1
    while num - 2 > 0:
        servicenameline = captured_lines[0].split()
        servicename = servicenameline[1].replace('"','')        
        protocolline = captured_lines[protnum].split()
        protocol = protocolline[0]
        if protocol not in ['tcp','udp']:
            print('# error: service %s has a protocol %s\n'%(servicename,protocol))
            with open('service-error.txt', 'a+') as file:
                msg='# error: service %s has a protocol %s\n'%(servicename,protocol)
                file.write(msg)
            break
        dstportstart = protocolline[2]
        if len(protocolline)>4:
            dstportend = protocolline[3] 
            if dstportend.isnumeric():
                dstportend = dstportend
            else:
                dstportend = dstportstart
        else:
            dstportend = dstportstart
        #print('edit %s\nset %s-portrange %s-%s\nnext\n'%(servicename,protocol,dstportstart,dstportend))
        # Open a file for writing
        with open('service.txt', 'a+') as file:
            msg='edit %s\nset %s-portrange %s-%s\nnext\n'%(servicename,protocol,dstportstart,dstportend)
            file.write(msg)
        protnum = protnum + 1
        num = num - 1

def getroute4():
    filename = 'h2.txt'
    start_marker = '  ip route'
    msg = ''
    index = 1000
    with open(filename,'r',encoding='utf-8') as file:
        for line in file:
            if line.startswith(start_marker):
                cfg = line.split()
                prefix = cfg[2]
                if cfg[-2] != 'description':              
                    if len(cfg) <= 4 and is_address(cfg[3]):
                        nexthop = cfg[3]
                        device = 'null'  
                        msg +='edit %s\nset dst %s\nset gateway %s\nset device %s\nnext\n'%(index,prefix,nexthop,device)
                        index= index+1  
                    elif len(cfg) > 4 and is_address(cfg[3]):
                        nexthop = cfg[3]
                        device = 'null' 
                        if cfg[4] == 10 or cfg[4] == 20:
                            distance = cfg[4]
                            msg +='edit %s\nset dst %s\nset gateway %s\nset distance %s\nset device %s\nnext\n'%(index,prefix,nexthop,distance,device)
                        else:    
                            msg +='edit %s\nset dst %s\nset gateway %s\nset device %s\nnext\n'%(index,prefix,nexthop,device)
                        index= index+1                  
                    elif len(cfg) > 5 and is_address(cfg[4]):
                        nexthop = cfg[4]
                        device = cfg[3]
                        if cfg[5] == 10 or cfg[5] == 20:
                            distance = cfg[5]
                            msg +='edit %s\nset dst %s\nset gateway %s\nset distance %s\nset device %s\nnext\n'%(index,prefix,nexthop,distance,device)
                        else:    
                            msg +='edit %s\nset dst %s\nset gateway %s\nset distance 20\nset device %s\nnext\n'%(index,prefix,nexthop,device)                                
                        index= index+1                  
                    else:
                        device = cfg[3]
                        msg +='edit %s\nset dst %s\nset device %s\nset distance 20\nnext\n'%(index,prefix,device)            
                        index= index+1
                elif cfg[-2] == 'description':
                    comment = cfg[-1]                
                    if is_address(cfg[3]):
                        nexthop = cfg[3]
                        device = 'null' 
                        if cfg[4] == 10 or cfg[4] == 20:
                            distance = cfg[4]
                            msg +='edit %s\nset dst %s\nset gateway %s\nset distance %s\nset device %s\nset comment %s\nnext\n'%(index,prefix,nexthop,distance,device,comment)
                        else:    
                            msg +='edit %s\nset dst %s\nset gateway %s\nset device %s\nnext\n'%(index,prefix,nexthop,device)
                        index= index+1
                    elif len(cfg) > 5 and is_address(cfg[4]):
                        nexthop = cfg[4]
                        device = cfg[3]
                        if cfg[5] == 10 or cfg[5] == 20:
                            distance = cfg[5]
                            msg +='edit %s\nset dst %s\nset gateway %s\nset distance %s\nset device %s\nset comment %s\nnext\n'%(index,prefix,nexthop,distance,device,comment)
                        else:    
                            msg +='edit %s\nset dst %s\nset gateway %s\nset device %s\nset comment %s\nnext\n'%(index,prefix,nexthop,device,comment)                                
                        index= index+1
                    else:
                        device = cfg[3]
                        msg +='edit %s\nset dst %s\nset device %s\nset distance 20\nset comment %s\nnext\n'%(index,prefix,device,comment)            
                        index= index+1
    with open('route.txt', 'a+') as file:
        file.write(msg)
        print(msg)

def getpolicy():
    filename = 'h2.txt'
    start_marker = 'rule id'
    end_marker = 'exit'
    capturing = False
    captured_lines = []
    index = 1000

    with open(filename,'r',encoding='utf-8') as file:
        for line in file:
            if line.startswith(start_marker):
                capturing = True
                captured_lines.append(line.strip())
            elif line.startswith(end_marker) and capturing:
                capturing = False
                captured_lines.append(line.strip())
                PolicyTrans(index,captured_lines)     
                index = index +1
                captured_lines = []       
            elif capturing:
                captured_lines.append(line.strip())

def PolicyTrans(index,captured_lines):
    action = captured_lines[1].split()[1]
    search_srcintf = "src-zone"
    search_dstintf = "dst-zone"
    search_srcaddr = "src-addr"
    search_dstaddr = "dst-addr"
    search_service = "service"
    srcintf = [i for i, x in enumerate(captured_lines) if search_srcintf in x]
    dstintf= [i for i, x in enumerate(captured_lines) if search_dstintf in x]
    srcaddr = [i for i, x in enumerate(captured_lines) if search_srcaddr in x]
    dstaddr = [i for i, x in enumerate(captured_lines) if search_dstaddr in x]
    service = [i for i, x in enumerate(captured_lines) if search_service in x]
    srcintf=srcintf[0]
    dstintf=dstintf[0]
    srcaddr=srcaddr[0]
    dstaddr=dstaddr[0]
    service=service[0]
    srcintf = captured_lines[srcintf].split()[1]
    dstintf = captured_lines[dstintf].split()[1]
    srcaddr = captured_lines[srcaddr].split()[1]
    dstaddr = captured_lines[dstaddr].split()[1]
    service = captured_lines[service].split()[1]
    print('%s%s%s%s%s%s%s'%(index,srcintf,dstintf,srcaddr,dstaddr,service,action))

def getaddr():
    filename = 'h2.txt'
    start_marker = 'address "'
    end_marker = 'exit'
    capturing = False
    captured_lines = []
    index = 1000
    with open(filename,'r',encoding='utf-8') as file:
        for line in file:
            if line.startswith(start_marker):
                capturing = True
                captured_lines.append(line.strip())
            elif line.startswith(end_marker) and capturing:
                capturing = False
                captured_lines.append(line.strip())
                AddrTrans(captured_lines)     
                captured_lines = []       
            elif capturing:
                captured_lines.append(line.strip())

def AddrTrans(captured_lines):    
    if len(captured_lines) <= 2:
        print('empty addr')
    else:
        addr = []
        for index in range(len(captured_lines)-2):
            addrname = captured_lines[0].split()[1]
            if captured_lines[index+1].startswith('ip ') and captured_lines[index+1].startswith('description'):
                addr.append(captured_lines[index+1].split()[1])
                desc = captured_lines[index+1]
                print('%s %s %s'%(addrname,addr,desc))
            elif captured_lines[index+1].startswith('ip '):
                addr.append(captured_lines[index+1])
            print('%s'%(addr))

def main():
    try:
        #getservice()
        #getroute4()
        getpolicy()
        #getaddr()
    except Exception as e:
        print(e)

if __name__ == '__main__':
    main()
