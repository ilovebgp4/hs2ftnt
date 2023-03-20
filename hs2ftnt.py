#!/usr/local/bin/python3
# -*- coding: UTF-8 -*-
# @Time    : 2022/08/18
# @Author  : Chen Jiang
# @Mail    : chenjiang@microshield.com.cn

import re
import ipaddress
import string

class FortiAddressInfo:
    def __init__(self):
        self.name = ""
        self.description = ""
        self.ishost = False
        self.iphost = ""


class FortiAddressGroup:
    def __init__(self):
        self.name = ""
        self.description = ""
        self.infonames = []


class HsAddressInfo:
    def __init__(self):
        self.name = ""
        self.description = ""

        self.ips = []
        self.members = []
        self.hosts = []

        self.singleiphost = False

    def toString(self):
        xstr = ""
        if len(self.name) == 0:
            return xstr
        xstr += "hs address,name:{0}\n".format(self.name)
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


class HsPolicyInfo:
    """
    HS的rule配置
rule id 26
  action permit
  log policy-deny
  log session-start
  log session-end
  src-zone "trust"
  dst-zone "untrust"
  src-addr "deny-public net"
  dst-addr "Any"
  dst-ip 172.18.218.99/32
  service "Any"
  description "禁止访问公网"
  name "rule26"
  disable
exit
    """
    def __init__(self):
        self.name = ""
        self.description = ""
        self.disable = ""
        self.action = ""

        #log
        self.log_session_start = ""
        self.log_session_end = ""

        #
        self.src_zone = ""
        self.dst_zone = ""

        self.src_addrs = []
        self.dst_addrs = []

        self.src_ips = []
        self.dst_ips = []

        self.service = []

    def toString(self):
        if len(self.src_zone) == 0 and len(self.dst_zone) == 0 and len(self.src_addrs) == 0 and len(self.dst_addrs) == 0 and len(self.src_ips) == 0 and len(self.dst_ips) == 0 and len(self.service) == 0 :
            return ""
        xstr = "HS Rule\n"
        if len(self.name) > 0:
            xstr += "\tname:{0}\n".format(self.name)
        if len(self.description) > 0:
            xstr += "\tdescription:{0}\n".format(self.description)
        if len(self.disable) > 0:
            xstr += "\tdisable:{0}\n".format(self.disable)
        if len(self.action) > 0:
            xstr += "\taction:{0}\n".format(self.action)

        #log
        if len(self.log_session_start) > 0:
            xstr += "\tlog_session_start:{0}\n".format(self.log_session_start)
        if len(self.log_session_end) > 0:
            xstr += "\tlog_session_end:{0}\n".format(self.log_session_end)

        #
        if len(self.src_zone) > 0:
            xstr += "\tsrc_zone:{0}\n".format(self.src_zone)
        if len(self.dst_zone) > 0:
            xstr += "\tdst_zone:{0}\n".format(self.dst_zone)

        if len(self.src_addrs) > 0:
            xstr += "\tsrc_addrs:{0}\n".format(",".join(self.src_addrs))
        if len(self.dst_addrs) > 0:
            xstr += "\tdst_addrs:{0}\n".format(",".join(self.dst_addrs))

        if len(self.src_ips) > 0:
            xstr += "\tsrc_ips:{0}\n".format(",".join(self.src_ips))
        if len(self.dst_ips) > 0:
            xstr += "\tdst_ips:{0}\n".format(",".join(self.dst_ips))

        if len(self.service) > 0:
            xstr += "\tservice:{0}\n".format(",".join(self.service))

        return xstr

def analyseHsAddressBlock(lines):
    """
    分析一段address .... exit多行字符串，构造一个原始定义
    输入参数：address .... exit多行字符串
    返回信息：HsAddressInfo
    """
    retobj = HsAddressInfo()

    for linestr in lines:
        xlinestr = linestr.strip()
        if len(xlinestr) == 0:
            continue
        elif xlinestr == "exit":
            return retobj
        if xlinestr.startswith("address"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xf = xfs[1]
                xf = xf.replace(" ", "")
                retobj.name = xf
        elif xlinestr.startswith("description"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xf = xfs[1]
                xf = xf.replace(" ", "")
                retobj.description = xf
        elif xlinestr.startswith("ip"):
            xfs = xlinestr.split()
            if len(xfs) >= 2:
                xf = xfs[1].strip()
                retobj.ips.append(xf)
        elif xlinestr.startswith("member"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xf = xfs[1].strip()
                xf = xf.replace(" ", "")
                retobj.members.append(xf)
        elif xlinestr.startswith("host"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xf = xfs[1].strip()
                xf = xf.replace(" ", "")
                retobj.hosts.append(xf)
    return retobj


def analyseHsPolicyBlock(lines):
    """
    分析一段rule id .... exit多行字符串，构造一个HS策略原始定义
    :param lines: rule id .... exit多行字符串
    :return: HsPolicyInfo
    """
    retobj = HsPolicyInfo()

    for linestr in lines:
        xlinestr = linestr.strip()
        if len(xlinestr) == 0:
            continue
        elif xlinestr.startswith("rule id"):
            continue
        elif xlinestr == "exit":
            return retobj
        if xlinestr.startswith("name"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                retobj.name = xfs[1].strip()
        elif xlinestr.startswith("description"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                retobj.description = xfs[1].strip()
        elif xlinestr.startswith("disable"):
            retobj.disable = "disable"
        elif xlinestr.startswith("action"):
            xfs = xlinestr.split()
            if len(xfs) >= 2:
                xf = xfs[1].strip()
                if xf.lower() == "permit":
                    xf = "accept"
                retobj.action = xfs[1].strip()
        elif xlinestr.startswith("log"):
            retobj.log_session_end = "log"
            xfs = xlinestr.split()
            if len(xfs) >= 2:
                xf = xfs[1].strip()
                if xf == "session-start":
                    retobj.log_session_start = "log"
        elif xlinestr.startswith("src-zone"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xf = xfs[1].strip()
                if xf.lower() == "any":
                    xf = "all"
                retobj.src_zone = xf
        elif xlinestr.startswith("dst-zone"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xf = xfs[1].strip()
                if xf.lower() == "any":
                    xf = "all"
                retobj.dst_zone = xf
        elif xlinestr.startswith("src-addr"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xf = xfs[1].strip().replace(" ", "")
                if xf.lower() == "any":
                    xf = "all"
                retobj.src_addrs.append(xf)
        elif xlinestr.startswith("dst-addr"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xf = xfs[1].strip().replace(" ", "")
                if xf.lower() == "any":
                    xf = "all"
                retobj.dst_addrs.append(xf)
        elif xlinestr.startswith("src-ip"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xf = xfs[1].strip().replace(" ", "")
                if xf.lower() == "any":
                    xf = "all"
                retobj.src_ips.append(xf)
        elif xlinestr.startswith("dst-ip"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xf = xfs[1].strip().replace(" ", "")
                if xf.lower() == "any":
                    xf = "all"
                retobj.dst_ips.append(xf)
        elif xlinestr.startswith("service"):
            xfs = xlinestr.split("\"")
            if len(xfs) >= 2:
                xf = xfs[1].strip().replace(" ", "")
                if xf.lower() == "any":
                    xf = "ALL"
                retobj.service.append(xf)
    return retobj


def addFortiAddressInfo(fortiAddressInfos, na, ishost, iphost):
    """
    将指定名字、类型、主机信息的address信息添加到forti的地址信息列表中
    :return:
    """
    if len(na) == 0 or len(iphost) == 0:
        return

    xinfo = FortiAddressInfo()
    xinfo.name = na
    xinfo.ishost = ishost
    xinfo.iphost = iphost
    fortiAddressInfos.append(xinfo)

    return fortiAddressInfos


def getFortiAddressInfoNameByIphost(fortiAddressInfos, iphost):
    """
    根据一个iphost查找对应的名字
    :param fortiInfos:
    :param iphost:
    :return:
    """
    if len(iphost) == 0:
        return
    for xinfo in fortiAddressInfos:
        if iphost == xinfo.iphost:
            return xinfo.name
    return ""


def replaceHsAddressMember(oneaddr, addresses):
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
                replaceHsAddressMember(xaddr, addresses)
                for xip in xaddr.ips:
                    oneaddr.ips.append(xip)
                for xhost in xaddr.hosts:
                    oneaddr.hosts.append(xhost)
    oneaddr.members = []


def fetchHsSingleIphost2Forti(addresses):
    """
    遍历所有的address，找出里面只有一个ip或者host的address，这种address不能更改name，不重新命名
    :param addresses:
    :return: fortininfos 里面包含所有的单个ip/host元素
    """
    fortiinfos = []
    for xaddress in addresses:
        if len(xaddress.ips) + len(xaddress.hosts) == 1:
            xaddress.singleiphost = True
            xfortiinfo = FortiAddressInfo()
            xfortiinfo.name = xaddress.name
            xfortiinfo.description = xaddress.description
            if len(xaddress.hosts) == 1:
                xfortiinfo.ishost = True
                xfortiinfo.iphost = xaddress.hosts[0]
            else:
                xfortiinfo.iphost = xaddress.ips[0]
            fortiinfos.append(xfortiinfo)
    return fortiinfos


def fetchHsIphost2Forti(addresses,fortiinfos,fortigroups):
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
        xfortigroup = FortiAddressGroup()
        xfortigroup.name = xaddress.name
        xfortigroup.description = xaddress.description

        #ips
        for xip in xaddress.ips:
            xname = getFortiAddressInfoNameByIphost(fortiinfos,xip)
            if len(xname) == 0:
                #2、添加fortiinfo
                xname = xip

                xfortiinfo = FortiAddressInfo()
                xfortiinfo.name = xname
                xfortiinfo.ishost = False
                xfortiinfo.iphost = xip

                fortiinfos.append(xfortiinfo)
            #3、将名字加入group的names
            xfortigroup.infonames.append(xname)

        for xhost in xaddress.hosts:
            xname = getFortiAddressInfoNameByIphost(fortiinfos, xhost)
            if len(xname) == 0:
                # 2、添加fortiinfo
                xname = xhost

                xfortiinfo = FortiAddressInfo()
                xfortiinfo.name = xname
                xfortiinfo.ishost = True
                xfortiinfo.iphost = xhost

                fortiinfos.append(xfortiinfo)
            # 3、将名字加入group的names
            xfortigroup.infonames.append(xname)

        #1\添加fortigroup
        fortigroups.append(xfortigroup)

    return fortiinfos,fortigroups


def generateFortiAddressString(fortiinfos,fortigroups):
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

def addHsPolicyIps2FortiAddressInfo(hspolicys,fortiaddressinfos):
    """
    HS的策略中，包含了大量的src-ip,dst-ip，格式的地址信息，将这一部分信息添加到forti的地址信息中，名字起名为ip-地址信息。

    src-ip "192.168.0.1/24"   --->   name  192.168.0.1/24   member ：192.168.0.1/24

    添加完以后，policy中的所有src-ips,dst-ips都不存在，并入到src_addrs,dst_addrs中
    :param hspolicys:
    :param fortiaddressinfos:
    :return:
    """
    for xhspolicy in hspolicys:
        if len(xhspolicy.src_ips) > 0:
            for xiphost in xhspolicy.src_ips:
                xname = getFortiAddressInfoNameByIphost(xiphost)
                if len(xname) == 0:
                    xname = xiphost
                    addFortiAddressInfo(fortiaddressinfos, xname, True, xiphost)
                xhspolicy.src_addrs.append(xname)
            xhspolicy.src_ips = []

        if len(xhspolicy.dst_ips) > 0:
            for xiphost in xhspolicy.dst_ips:
                xname = getFortiAddressInfoNameByIphost(xiphost)
                if len(xname) == 0:
                    xname = xiphost
                    addFortiAddressInfo(fortiaddressinfos, xname, True, xiphost)
                xhspolicy.dst_addrs.append(xname)
            xhspolicy.dst_ips = []

    return fortiaddressinfos


def generateFortiPolicyString(hspolicys):
    """
    生成forti policy对象的字符串
config firewall policy
    edit 1
        set status disable
        set name "policy-name"
        set uuid 9aaa4152-c56d-51ed-bd9e-a8a3839b0267
        set srcintf "port1"
        set dstintf "port2"
        set action accept
        set srcaddr "Internal"
        set dstaddr "gmail.com" "Microsoft Office 365"
        set schedule "always"
        set service "FTP" "NFS"
        set logtraffic all
        set logtraffic-start enable
        set comments "this is comment"
    next
end
    :param hspolicys:  HS的policy信息
    :return:forti格式定义policy信息
    """
    xstr = "config firewall policy\n"
    xindex = 1
    for xhspolicy in hspolicys:
        xstr += "\tedit {0}\n".format(xindex)
        xindex += 1
        if len(xhspolicy.name) > 0:
            # name "SD-WAN测试"
            # set name "policy-name"
            xstr += "\t\tset name \"{0}\"\n".format(xhspolicy.name)

        if len(xhspolicy.action) > 0:
            # action permit/deny
            # set action accept/deny
            if xhspolicy.action == "permit":
                xstr += "\t\tset action accept\n"
            else:
                xstr += "\t\tset action {0}\n".format(xhspolicy.action)

        if len(xhspolicy.disable) > 0:
            # set status disable
            xstr += "\t\tset status disable\n"

        if len(xhspolicy.log_session_start) > 0 or len(xhspolicy.log_session_end):
            # set logtraffic all
            xstr += "\t\tset logtraffic all\n"
            if len(xhspolicy.log_session_start) > 0:
                xstr += "\t\tset logtraffic-start enable\n"

        if len(xhspolicy.src_zone) > 0:
            # src-zone "untrust"
            # set srcintf "port1"
            xstr += "\t\tset srcintf \"{0}\"\n".format(xhspolicy.src_zone)

        if len(xhspolicy.dst_zone) > 0:
            # dst-zone "trust"
            # set srcintf "port1"
            xstr += "\t\tset dstintf \"{0}\"\n".format(xhspolicy.dst_zone)

        if len(xhspolicy.src_addrs) > 0:
            # src-addr "Internal"
            # src-addr "Internal222"
            # set srcaddr "Internal" "Internal222"
            xstr += "\t\tset srcaddr"
            for xaddr in xhspolicy.src_addrs:
                if len(xaddr) > 0:
                    xstr += " \"{0}\"".format(xaddr)
            xstr += "\n"

        if len(xhspolicy.dst_addrs) > 0:
            # dst-addr "Internal"
            # dst-addr "Internal222"
            # set dstaddr "Internal" "Internal222"
            xstr += "\t\tset dstaddr"
            for xaddr in xhspolicy.dst_addrs:
                if len(xaddr) > 0:
                    xstr += " \"{0}\"".format(xaddr)
            xstr += "\n"

        if len(xhspolicy.service) > 0:
            # service "ICMP"
            # service "velo-cloud-vcg"
            # set service "ICMP" "velo-cloud-vcg"
            xstr += "\t\tset service"
            for xservice in xhspolicy.service:
                if len(xservice) > 0:
                    xstr += " \"{0}\"".format(xservice)
            xstr += "\n"

        if len(xhspolicy.description) > 0:
            # description "SD-WAN测试"
            # set comment "policy-name"
            xstr += "\t\tset comment \"{0}\"\n".format(xhspolicy.description)

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
    filename = "h2.txt"

    captured_type = ""
    captured_lines = []

    hsPolicys = []
    hsAddresses = []

    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            if line.startswith("address") and len(captured_type) == 0:
                captured_type = "address"
                captured_lines.append(line.strip())
            elif line.startswith("rule id") and len(captured_type) == 0:
                captured_type = "rule"
                captured_lines.append(line.strip())
            elif line.startswith("exit") and len(captured_type) > 0:
                captured_lines.append(line.strip())
                if captured_type == "address":
                    xaddress = analyseHsAddressBlock(captured_lines)
                    if len(xaddress.name) > 0 and (len(xaddress.ips) > 0 or len(xaddress.hosts) > 0 or len(xaddress.members) > 0):
                        hsAddresses.append(xaddress)
                elif captured_type == "rule":
                    xpolicy = analyseHsPolicyBlock(captured_lines)
                    if len(xpolicy.src_zone) == 0 or len(xpolicy.dst_zone) == 0 or len(xpolicy.src_addrs) == 0 or len(xpolicy.dst_addrs) == 0 or len(xpolicy.src_ips) == 0 or len(xpolicy.dst_ips) == 0 or len(xpolicy.service) == 0:
                        hsPolicys.append(xpolicy)

                captured_type = ""
                captured_lines = []
            elif len(captured_type) > 0:
                captured_lines.append(line.strip())

    # 打印一下提取的address信息
    for xhsaddress in hsAddresses:
        print(xhsaddress.toString())
    # 打印一下提取的policy信息
    for xhspolicy in hsPolicys:
        print(xhspolicy.toString())
    #替换member
    for xhsaddress in hsAddresses:
        replaceHsAddressMember(xhsaddress,hsAddresses)

    #只有单个ip或者只有单个host的，这部分不需要针对ip/host重新命名
    xforti_address_infos = fetchHsSingleIphost2Forti(hsAddresses)

    #获取多个ip地址的address对象，转换为forti对象
    xforti_address_groups = []
    xforti_address_infos,fortigroups = fetchHsIphost2Forti(hsAddresses, xforti_address_infos, xforti_address_groups)

    #将policy中的单个src_ip，dst_ip对象添加到forti的地址address对象中
    addHsPolicyIps2FortiAddressInfo(hsPolicys,xforti_address_infos)

    #生成forti 地址对象的字符串
    xforti_address_str = generateFortiAddressString(xforti_address_infos,fortigroups)

    #生成forti policy对象的字符串
    xforti_policy_str = generateFortiPolicyString(hsPolicys)

    print(xforti_address_str)
    print(xforti_policy_str)
    with open('policy-addr.txt', 'a+') as file:
        file.write(xforti_address_str)
    with open('policy.txt', 'a+') as file:
        file.write(xforti_policy_str)    


def main():
    try:
        getservice()
        #getroute4()
        #getpolicy()
    except Exception as e:
        print(e)

if __name__ == '__main__':
    main()
