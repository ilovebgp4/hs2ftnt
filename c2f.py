#!/usr/local/bin/python3
# -*- coding: UTF-8 -*-
# @Time    : 2022/08/18
# @Author  : Chen Jiang
# @Mail    : chenjiang@microshield.com.cn

import getopt
from os import lstat
from tkinter import E
import re


class TNatRule:
    def __init__(self):
        self.srcIp = ''
        self.srcPort = 0
        self.dstIp = ""
        self.dstPort = 0
        self.srcZone = ""
        self.dstZone = ""


def getcfg():
    rules = []

    filename = 'asa.cfg'
    try:
        cfg = open(filename, 'r', encoding='utf-8')
        line = cfg.readlines()
        for a in line:
            a = a.strip()
            tfields = a.split()
            nbOfTfields = len(tfields)
            if nbOfTfields >= 9:
                # ['nat', '(LAN,WAN)', 'source', 'static', '10.1.50.99', '202.170.139.131', 'service', '8013', '8013'] 最少都有九个fields
                if tfields[0].upper() == 'NAT' and tfields[nbOfTfields - 1].upper() != 'INACTIVE':
                    tindex=0
                    if tfields[2].lower() == 'source' and tfields[3].lower() == 'static' and isIpv4(
                            tfields[4]) and isIpv4(
                            tfields[5]) and tfields[7].isdigit() and tfields[8].isdigit():
                        tindex=4
                    elif nbOfTfields >= 10 and tfields[3].lower() == 'source' and tfields[
                        4].lower() == 'static' and isIpv4(tfields[5]) and isIpv4(
                            tfields[6]) and tfields[8].isdigit() and tfields[9].isdigit():
                        tindex=5
                    if tindex > 0:
                        print(a)
                        tnatrule = TNatRule()
                        tnatrule.srcIp = tfields[tindex]
                        tnatrule.dstIp = tfields[tindex+1]
                        tnatrule.srcPort = int(tfields[tindex+3])
                        tnatrule.dstPort = int(tfields[tindex+4])
                        tnatrule.srcZone, tnatrule.dstZone = getZone(tfields[1])

                        rules.append(tnatrule)
    except Exception as e:
        print(e)
        print(e.args)

    print("output nat rules:")
    seq = 10
    for natrule in rules:
        print("edit %s\n set extip %s\n set mappedip %s\n set extintf %s\n set portforward enable\n set extport %s \n set mappedport %s\n next"%(seq,natrule.dstIp,natrule.srcIp,natrule.dstZone,natrule.srcPort,natrule.dstPort))
        seq+= 10
    return rules


def isIpv4(str):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(str):
        return True
    else:
        return False


def getZone(src):
    try:
        p1 = re.compile(r'[(](.*?)[)]', re.S)  # 最小匹配
        xcontent = re.findall(p1, src)
        if len(xcontent) > 0:
            l = xcontent[0].split(',')
            if len(l) == 2:
                return l[0], l[1]
    except Exception as e:
        print(e)

    return None


def main():
    try:
        getcfg()
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
