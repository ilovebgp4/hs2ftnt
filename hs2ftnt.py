#!/usr/local/bin/python3
# -*- coding: UTF-8 -*-
# @Time    : 2022/08/18
# @Author  : Chen Jiang
# @Mail    : chenjiang@microshield.com.cn

import re
import ipaddress
import string

class FortiInfo:
    def __init__(self):
        self.name = ""
        self.description = ""
        self.ishost = False
        self.iphost = ""


class FortiGroup:
    def __init__(self):
        self.name = ""
        self.description = ""
        self.infonames = []


class AddressInfo:
    def __init__(self):
        self.name = ""
        self.description = ""

        self.ips = []
        self.members = []
        self.hosts = []

        self.fortiips = []
        self.fortihosts = []

        self.singleiphost = False


    def toForti(self):
        xstr = ""
        if len(self.name) == 0:
            return xstr
        xstr += "name:{0}\n".format(self.name)
        if len(self.description) > 0:
            xstr += "description:{0}\n".format(self.description)

        if len(self.ips) > 0:
            xstr += "ips:\n"
            for ip in self.ips:
                xstr += "\t{0}\n".format(ip)

        if len(self.members) > 0:
            xstr += "members:\n"
            for member in self.members:
                xstr += "\t{0}\n".format(member)

        if len(self.hosts) > 0:
            xstr += "hosts:\n"
            for host in self.hosts:
                xstr += "\t{0}\n".format(host)

        return xstr


def analyseAddressBlock(lines):
    """
    分析一段address .... exit多行字符串，构造一个原始定义
    输入参数：address .... exit多行字符串
    返回信息：AddressInfo
    """
    retobj = AddressInfo()

    for linestr in lines:
        xlinestr = linestr.strip()
        if len(xlinestr) == 0:
            continue
        elif xlinestr == "exit":
            return retobj
        if xlinestr.startswith("address"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xfs = xfs[1]
                xf = xfs.replace(" ", "")
                retobj.name = xf
        elif xlinestr.startswith("description"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xfs = xfs[1]
                xf = xfs.replace(" ", "")
                retobj.description = xf
        elif xlinestr.startswith("ip"):
            xfs = xlinestr.split()
            if len(xfs) >= 2:
                xf = xfs[1].strip()
                retobj.ips.append(xf)
        elif xlinestr.startswith("member"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xfs = xfs[1]
                xf = xfs.replace(" ", "")
                retobj.members.append(xf)
        elif xlinestr.startswith("host"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xfs = xfs[1]
                xf = xfs.replace(" ", "")
                retobj.hosts.append(xf)
    return retobj


def addFortiInfo(fortiInfos, na, ishost, iphost):
    """
    将指定名字、类型、主机信息的address信息添加到forti的地址信息列表中
    :return:
    """
    if len(na) == 0 or len(iphost) == 0:
        return

    xinfo = FortiInfo()
    xinfo.name = na
    xinfo.ishost = ishost
    xinfo.iphost = iphost
    fortiInfos.append(xinfo)

    return fortiInfos


def getIphostName(fortiInfos, iphost):
    """
    根据一个iphost查找对应的名字
    :param fortiInfos:
    :param iphost:
    :return:
    """
    if len(iphost) == 0:
        return
    for xinfo in fortiInfos:
        if iphost == xinfo.iphost:
            return xinfo.name
    return ""


def replaceMember(oneaddr, addresses):
    """
    在addresses中查找所有的address，替换前面address参数中的member内容
    :param oneaddr:
    :param addresses:
    :return:  成功替换返回True，没有替换返回False
    """
    if oneaddr is None or addresses is None:
        return False
    if len(oneaddr.members) == 0:
        return False
    for xmemeber in oneaddr.members:
        for xaddr in addresses:
            if xaddr.name == oneaddr.name:
                continue
            # 比较xaddr的名字=xmemeber的名字，那么进行替换
            if xmemeber == xaddr.name:
                replaceMember(xaddr, addresses)
                for xip in xaddr.ips:
                    oneaddr.ips.append(xip)
                for xhost in xaddr.hosts:
                    oneaddr.hosts.append(xhost)
    oneaddr.members = []


def fetchSingleIphost(addresses):
    """
    遍历所有的address，找出里面只有一个ip或者host的address，这种address不能更改name，不重新命名
    :param addresses:
    :return: fortininfos 里面包含所有的单个ip/host元素
    """
    fortiinfos = []
    for xaddress in addresses:
        if len(xaddress.ips) + len(xaddress.hosts) == 1:
            xaddress.singleiphost = True
            xfortiinfo = FortiInfo()
            xfortiinfo.name = xaddress.name
            xfortiinfo.description = xaddress.description
            if len(xaddress.hosts) == 1:
                xfortiinfo.ishost = True
                xfortiinfo.iphost = xaddress.hosts[0]
            else:
                xfortiinfo.iphost = xaddress.ips[0]
            fortiinfos.append(xfortiinfo)
    return fortiinfos


def fetchIphost(addresses,fortiinfos,fortigroups):
    """
    遍历获取所有的addresses，找出里面所有的不是single的信息，将name添加到groups，将每一个iphost构造一个fortininfo，并且把对应名字添加到groups的infonames中
    :param addresses:
    :param fortiinfos:
    :param fortigroups:
    :return:
    """

    for xaddress in addresses:
        if xaddress.singleiphost:
            continue
        #1、添加fortigroup
        xfortigroup = FortiGroup()
        xfortigroup.name = xaddress.name
        xfortigroup.description = xaddress.description

        #ips
        for xip in xaddress.ips:
            xname = getIphostName(fortiinfos,xip)
            if len(xname) == 0:
                #2、添加fortiinfo
                xname = xip

                xfortiinfo = FortiInfo()
                xfortiinfo.name = xname
                xfortiinfo.ishost = False
                xfortiinfo.iphost = xip

                fortiinfos.append(xfortiinfo)
            #3、将名字加入group的names
            xfortigroup.infonames.append(xname)

        for xhost in xaddress.hosts:
            xname = getIphostName(fortiinfos, xhost)
            if len(xname) == 0:
                # 2、添加fortiinfo
                xname = xhost

                xfortiinfo = FortiInfo()
                xfortiinfo.name = xname
                xfortiinfo.ishost = True
                xfortiinfo.iphost = xhost

                fortiinfos.append(xfortiinfo)
            # 3、将名字加入group的names
            xfortigroup.infonames.append(xname)

        #1\添加fortigroup
        fortigroups.append(xfortigroup)

    return fortiinfos,fortigroups


def generateFortiString(fortiinfos,fortigroups):
    xstr = ""

    #1、生成group
    """
config firewall addrgrp
    edit "Goolge"
        set uuid 91c787fc-c4a5-51ed-a8ce-0fec2e97bb27
        set member "Google IP1" "Google IP2" "Google-Host1" "Google-host2"
    next
end
    """
    xstr += "config firewall addrgrp\n"
    for xgroup in fortigroups:
        xstr += "\tedit \"{0}\"\n".format(xgroup.name)
        if len(xgroup.description) > 0:
            xstr += "\t\tdescription \"{0}\"\n".format(xgroup.description)
        xstr += "\t\tset member"
        for xname in xgroup.infonames:
            xstr += " \"{0}\"".format(xname)
        xstr += "\n"
        xstr += "\tnext\n"
    xstr += "end\n\n"
    #2、生成ip/host
    """
config firewall address
    edit "Google IP1"
        set subnet 104.18.7.10/32
    next
    edit "Google-host2"
        set type fqdn
        set fqdn "www.169.com"
    next
end
    """
    xstr += "config firewall address\n"
    for xinfo in fortiinfos:
        xstr += "\tedit \"{0}\"\n".format(xinfo.name)
        if len(xinfo.description) > 0:
            xstr += "\t\tdescription \"{0}\"\n".format(xinfo.description)
        if xinfo.ishost:
            xstr += "\t\tset type fqdn\n"
            xstr += "\t\tset fqdn \"{0}\"\n".format(xinfo.iphost)
        else:
            xstr += "\t\tset subnet \"{0}\"\n".format(xinfo.iphost)
        xstr += "\tnext\n"
    xstr += "end\n"

    return xstr

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
                    if len(cfg) <= 4 and is_address(cfg[3]):
                        nexthop = cfg[3]
                        device = 'null'  
                        msg +='edit %s\nset dst %s\nset gateway %s\nset device %s\nset comment %s\nnext\n'%(index,prefix,nexthop,device,comment)
                        index= index+1  
                    elif len(cfg) > 4 and is_address(cfg[3]):
                        nexthop = cfg[3]
                        device = 'null' 
                        if cfg[4] == 10 or cfg[4] == 20:
                            distance = cfg[4]
                            msg +='edit %s\nset dst %s\nset gateway %s\nset distance %s\nset device %s\nset comment %s\nnext\n'%(index,prefix,nexthop,distance,device,comment)
                        else:    
                            msg +='edit %s\nset dst %s\nset gateway %s\nset device %s\nset comment %s\nnext\n'%(index,prefix,nexthop,device,comment)
                        index= index+1                  
                    elif len(cfg) > 5 and is_address(cfg[4]):
                        nexthop = cfg[4]
                        device = cfg[3]
                        if cfg[5] == 10 or cfg[5] == 20:
                            distance = cfg[5]
                            msg +='edit %s\nset dst %s\nset gateway %s\nset distance %s\nset device %s\nset comment %s\nnext\n'%(index,prefix,nexthop,distance,device,comment)
                        else:    
                            msg +='edit %s\nset dst %s\nset gateway %s\nset distance 20\nset device %s\nset comment %s\nnext\n'%(index,prefix,nexthop,device,comment)                                
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

def getaddr():
    filename = "h2.txt"
    start_marker = 'address "'
    end_marker = 'exit'
    captured_lines = []
    addresses = []
    capturing = False

    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            if line.startswith(start_marker):
                capturing = True
                captured_lines.append(line.strip())
            elif line.startswith(end_marker) and capturing:
                capturing = False
                captured_lines.append(line.strip())
                xaddress = analyseAddressBlock(captured_lines)
                if len(xaddress.name) > 0 and (len(xaddress.ips) > 0 or len(xaddress.hosts) > 0 or len(xaddress.members) > 0):
                    addresses.append(xaddress)
                captured_lines = []
            elif capturing:
                captured_lines.append(line.strip())

    # 把每一个address中的ip,host转为forti的ip，host，将其中的member进行替换
    for xaddress in addresses:
        print(xaddress.toForti())
    #替换member
    for xaddress in addresses:
        replaceMember(xaddress,addresses)

    #只有单个ip或者只有单个host的，这部分不需要针对ip/host重新命名
    fortiinfos = fetchSingleIphost(addresses)

    #
    fortigroups = []
    fortiinfos,fortigroups = fetchIphost(addresses,fortiinfos,fortigroups)

    #
    xfortistr = generateFortiString(fortiinfos,fortigroups)

    print(xfortistr)
    with open('addr.txt', 'a+') as file:
        file.write(xfortistr)

def main():
    try:
        #getservice()
        #getroute4()
        #getpolicy()
        getaddr()
    except Exception as e:
        print(e)

if __name__ == '__main__':
    main()
