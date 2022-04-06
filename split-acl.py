from ipaddress import IPv4Network
import re


def get_hits(line):
    hitcnt_pattern = re.compile("\(hitcnt=\d+.*?\)")
    cluster_pattern = re.compile("\d+, \d+")
    hitstring = hitcnt_pattern.findall(line)[0]

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


def get_endpoint(eps):
    host, port = "any", "any"
    if eps[0] == "host":
        host = eps[1]
        eps = eps[2:]
    elif eps[0] == "any":
        eps = eps[1:]
    else:
        host = eps[0] + "/" + eps[1]
        host = eps[0] + "/" + str(IPv4Network(host).prefixlen)
        eps = eps[2:]

    if eps[0] == 'eq':
        port = eps[1]
        eps = eps[2:]
    elif eps[0] == 'range':
        port = eps[1] + "-" + eps[2]
        eps = eps[3:]

    return host, port, eps


def acl_parse(rule):
    rule = rule.lstrip().rstrip()
    parts = rule.split(" ")
    _, aclName, _, lineNumber, _, action, protocol = parts[:7]
    endpoints = parts[7:]
    sourceIP, sourcePort, endpoints = get_endpoint(endpoints)
    destIP, destPort, endpoints = get_endpoint(endpoints)
    
    timerangename = ""
    if 'time-range' in endpoints:
        timerangename = endpoints[endpoints.index('time-range')+1]
    
    hits = 0
    hits = get_hits(rule)

    rule_active = True
    if '(inactive)' in endpoints:
        rule_active = False

    acl_ref = ""
    if re.match("^0x", endpoints[-1]):
        acl_ref = endpoints[-1]

    return aclName, lineNumber, action, protocol, sourceIP, sourcePort, destIP, destPort, timerangename, hits, rule_active, acl_ref


def main():

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

    for rule in sample_acl:

        aclName, lineNumber, action, protocol, sourceIP, sourcePort, destIP, destPort, timerangename, hits, rule_active, acl_ref = acl_parse(rule)

        print("############################################################################################################")

        print(rule)

        print("            ACL Name: {}\n \
            Line Number: {}\n \
            Action: {}\n \
            Protocol: {}\n \
            Source IP: {}\n \
            Source Port(s): {}\n \
            Destination IP: {}\n \
            Destination Port(s): {} \n \
            Time-Range: {} \n \
            Hits: {} \n \
            Rule Active: {} \n \
            ACL Reference: {}".format(
                aclName, 
                lineNumber, 
                action, 
                protocol, 
                sourceIP, 
                sourcePort, 
                destIP, 
                destPort,
                timerangename,
                hits,
                rule_active,
                acl_ref
                )
            )


if __name__ == "__main__":
    main()
