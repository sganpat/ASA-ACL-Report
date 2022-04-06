'''
Name: asa-acl-report.py
Description: Cisco ASA Firewall ACL report script
'''

import re
# import sys

sample_acl = [
    '  access-list Profile_access_in line 96 extended permit tcp host 192.168.2.30 host 192.168.60.28 eq 1526 time-range Profilehardwaretest (hitcnt=0) (inactive) 0xb8777bf8',
    '  access-list CorpSys_access_in line 6 extended permit tcp any host 192.168.60.31 range 49152 65535 (hitcnt=2293) 0x5449d5e0',
    '  access-list CCSystems_access_in line 6 extended permit tcp host 192.168.4.31 host 192.168.47.59 eq 2000 (hitcnt=0) 0x85859ffd ',
    '  access-list FWGW1_access_in line 5 extended permit tcp 172.19.6.0 255.255.255.0 host 192.168.3.244 eq 1812 (hitcnt=0) 0xcb7e1707 ',
    '  access-list FCIS_PROD_access_in line 2 extended permit tcp 172.27.1.0 255.255.255.0 host 192.168.13.46 range 49152 65535 (hitcnt=0) 0x6f181dcb ',
    '  access-list VXRAIL_Sys_access_in line 2 extended permit udp 10.104.0.0 255.255.0.0 host 192.168.3.210 eq 135 (hitcnt=0) 0x8ab91f77 ',
    '  access-list Workstation_access_in line 7 extended permit icmp host 192.168.7.100 host 192.168.3.15 (hitcnt=0) 0x4381ad08 ',
    '  access-list DbaseSys_access_in line 2 extended deny ip host 192.168.8.0 host 192.168.4.41 inactive (hitcnt=0) (inactive) 0xd447bb33 ',
    '  access-list WAN_access_in line 548 extended permit tcp host 192.168.46.201 host 192.168.60.104 eq 8086 (hitcnt=0, 279, 0) 0x261092fc ',
    '  access-list SysMgmt_access_in line 6 extended permit udp host 192.168.61.7 host 192.168.3.244 eq domain (hitcnt=1049, 639, 410) 0xb4684901 ',
    '  access-list TestSys_access_in line 80 extended permit ip any host 192.168.51.41 (hitcnt=0, 0, 905) 0xbba64b24 '
]


def get_file(options, args):
    (options, args)
    lines = []
    f = open(args[0], "r")
    templines = f.readlines()
    f.close()
    for line in templines:
        line = line.replace("\n", "")
        line = line.replace("\r", "")
        lines.append(line)
    return lines


def get_hits(hitstring):
    cluster_pattern = re.compile("\d+, \d+")

    hitstring = hitstring.replace("(hitcnt=", "")
    hitstring = hitstring.replace(")", "")

    if cluster_pattern.match(hitstring):
        hitstring = hitstring.split(", ")
        hitstring = list(map(int, hitstring))
        hits = 0
        for i in range(1, len(hitstring)):
            hits += hitstring[i]
    else:
        hits = int(hitstring)

    return hits


def parse_acl(acl):

    acl_trim = acl.lstrip().rstrip()

    str_split_acl = acl_trim.split(" ") 

    acl_name = str_split_acl[1] 

    print("ACL Name: {}".format(acl_name))

    line_num = str_split_acl[2] + " " + str_split_acl[3]

    print("Line Number: {}".format(line_num))

    action = str_split_acl[5]

    print("Action: {}".format(action))

    protocol = str_split_acl[6]

    print("Protocol: {}".format(protocol))

    if str_split_acl[7] == 'host':
        source_ip = str_split_acl[8]
        source_mask = '255.255.255.255'
    else:
        source_ip = str_split_acl[7]
        source_mask = str_split_acl[8]

    print("Source IP: {}\nSource Mask:{}".format(source_ip, source_mask))

    if str_split_acl[9] == 'host':
        dest_ip = str_split_acl[10]
        dest_mask = '255.255.255.255'
    else:
        dest_ip = str_split_acl[9]
        dest_mask = str_split_acl[10]

    print("Destination IP: {}\nDestination Mask:{}".format(dest_ip, dest_mask))

    if str_split_acl[11] == 'eq':
        dest_service = str_split_acl[12]

    print("Destination Service: {}".format(dest_service))

    if 'time-range' in str_split_acl:
        timerangename = str_split_acl[str_split_acl.index('time-range')+1]

    print("Time Range: {}".format(timerangename))

    for item in str_split_acl:
        if '(hitcnt=' in item:
            hits = get_hits(item)

    print("Hits: {}".format(hits))

    if '(inactive)' in str_split_acl:
        rule_active = False
    else:
        rule_active = True

    print("Active: {}".format(rule_active))

    if re.match("^0x", str_split_acl[-1]):
        acl_ref = str_split_acl[-1]

    print("ACL Reference: {}".format(acl_ref))


for acl in sample_acl:
    print("##################")
    print(acl)
    parse_acl(acl)
