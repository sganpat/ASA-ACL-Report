'''
Name: asaaclreport.py
Description: Cisco ASA Firewall ACL report script
'''

from ipaddress import IPv4Network
import pandas as pd
import re


def get_file(filename):
    lines = []
    f = open(filename, "r")
    templines = f.readlines()
    f.close()
    for line in templines:
        line = line.replace("\n", "")
        line = line.replace("\r", "")
        lines.append(line)
    return lines


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


def split_acl(sample_acl):

    acl_list = []

    for rule in sample_acl:

        aclName, lineNumber, action, protocol, sourceIP, sourcePort, destIP, destPort, timerangename, hits, rule_active, acl_ref = acl_parse(rule)

        acl_list.append({
        #    'ACL' : rule, 
            'ACL Name' : aclName, 
            'Line Number' : lineNumber, 
            'Action' : action, 
            'Protocol' : protocol, 
            'Source IP' : sourceIP, 
            'Source Port' : sourcePort, 
            'Destination IP' : destIP, 
            'Destination Port' : destPort, 
            'Time-Range' : timerangename, 
            'Hits' : hits, 
            'Enabled' : rule_active, 
            'ACL Reference' : acl_ref
        })

    return pd.DataFrame.from_records(acl_list) 


def main():

    file = "test-files/access-list-cluster.txt"

    sample_acl=get_file(file)

    df = split_acl(sample_acl)

    rules_no_hit = []
    # unique ACL Names
    aclnames = pd.unique(df["ACL Name"])
    # interate each names
    for name in aclnames:
        df_acl = df[df["ACL Name"] == name]
        # unique lines
        lines = pd.unique(df_acl["Line Number"])
        # interate over each line
        for line in lines:
            df_line = df_acl[df_acl["Line Number"] == line]
            # unique protocols
            protocols = pd.unique(df_line["Protocol"])
            # interate over each protocol
            for protocol in protocols:
                df_protocol = df_line[df_line["Protocol"] == protocol]
                # Unique sources
                sources = pd.unique(df_protocol["Source IP"])
                # iterate over sources
                for source in sources:
                    df_source = df_protocol[df_protocol["Source IP"] == source]
                    df_hits = df_source[df_source["Hits"] == 0]
                    if len(df_source) == len(df_hits):
                        rules_no_hit.append("{},{},{},source,{}".format(name, line, protocol, source))
                # Unique destinations
                destinations = pd.unique(df_protocol["Destination IP"])
                # interate over destinations
                for destination in destinations:
                    df_destination = df_protocol[df_protocol["Destination IP"] == destination]
                    if len(df_destination) == len(df_destination[df_destination["Hits"] == 0]):
                        rules_no_hit.append("{},{},{},destination,{}".format(name, line, protocol, destination))
                # Unique ports
                ports = pd.unique(df_protocol["Destination Port"])
                # interate over destinations
                for port in ports:
                    df_port = df_protocol[df_protocol["Destination Port"] == port]
                    if len(df_port) == len(df_port[df_port["Hits"] == 0]):
                        rules_no_hit.append("{},{},{},port,{}".format(name, line, protocol, port))


    outfile = "test-files/asa-no-hits-20220406.csv"
    with open(outfile, 'w') as f:
        f.write('name,line,protocol,type,IP or Port\n')
        f.write('\n'.join(rules_no_hit))


if __name__ == "__main__":
    main()
    
