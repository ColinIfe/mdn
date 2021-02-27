import os
import networkx as nx
import calendar
import json
from igraph import *
from dateutil import parser
from urlparse import urlparse
from tqdm import *
import subprocess
from IPy import IP

import pyprind

'''
This module builds a graph from download metadata with fields as defined below
'''

data_fields = [
    'server_ts',
    'machine_guid',
    'enterprise_guid',
    'country',
    'file_sha2',
    'file_md5',
    'filename',
    'filesize',
    'url',
    'parent_file_sha2',
    'parent_url',
    'download_ip',
    'prevalence',
    'reputation_score',
    'referrer_url',
    'file_signer_issuer',
    'file_signer_subject',
    'file_directory',
    'file_type',
    'event',
]

""" 
Data pre-processing 
"""

# IPv4/6 Bogon List - removes invalid IPs for public use
disqualified_IPs = []
with open('build_graph/ipv4-shortbogons.txt', 'r') as f:
    disqualified_IPs.extend([x.split('\n')[0] for x in f.readlines()[1:]])

with open('build_graph/ipv6-shortbogons.txt', 'r') as f:
    disqualified_IPs.extend([x.split('\n')[0] for x in f.readlines()[1:]])


def IP_in_subnet(test_IP, bogons_list):
    try:
        IP(test_IP)
        for subnet in bogons_list:
            if IP(test_IP) in IP(subnet):
                return True
        return False
    except:
        return False


def _qualified(values):
    if values[8] != 'NULL' or \
            (values[11] != 'NULL' and not IP_in_subnet(values[11], disqualified_IPs)) \
            or values[14] != 'NULL':
        return True


def _matchup(values, droppers):
    if values[9] in droppers or values[8] != 'NULL' or \
            (values[11] != 'NULL' and not IP_in_subnet(values[11], disqualified_IPs)) or \
            values[14] != 'NULL':
        return True


def qualified_dropper(inFile):
    droppers = set()
    with open(inFile, 'r') as f:
        for line in tqdm(f):
            line = line.strip()
            values = line.split('\t')
            if len(values) == len(data_fields):
                if _qualified(values):
                    droppers.add(values[4])
    return droppers


def filter_rawdata(inFile, outFile, droppers):
    outHandler = open(outFile, 'w')
    with open(inFile, 'r') as f:
        for line in tqdm(f):
            line = line.strip()
            values = line.split('\t')
            if len(values) == len(data_fields):
                if _matchup(values, droppers):
                    outHandler.write('\t'.join(values) + '\n')
    outHandler.close()


'''
Graph-building code
'''

nid = 0
node_attributes = ['type', 'data', 'score', 'name', 'prevalence', 'status', 'fileType']
name2id = {}
node2events = {}
event2timestamp = {}


def get_time(str_time):
    return calendar.timegm((parser.parse(str_time)).timetuple())


def process_url(url):
    try:
        parsed = urlparse(url)
    except:
        return None, None, None, None
    try:
        return parsed.scheme, parsed.hostname, parsed.path, parsed.port
    except:
        return parsed.scheme, parsed.hostname, parsed.path, None


def add_node_event_pairing(nid, eid):
    try:
        node2events[nid].append(eid)
    except:
        node2events[nid] = [eid]


def get_parent_file_node(line):
    if line['parent_file_sha2'] == 'NULL':
        return None, None

    global nid
    d = {'type': 'file', 'name': line['parent_file_sha2'], 'score': str(0), 'data': 'parent', 'prevalence': -1,
         'size': -1, 'status': 1, 'event': [line['event']]}
    # parent file has always prevalence -1 unless we have its prevalence info, i.e. a parent file was a file
    # status == 1 implies that score is artificial

    # Note that insert_method wil block repeated insertion, hence this line
    if line['parent_file_sha2'] in name2id:
        return name2id[line['parent_file_sha2']], d

    nid += 1
    name2id[line['parent_file_sha2']] = str(nid)
    return str(nid), d


def get_file_node(line):
    if line['file_sha2'] == 'NULL':
        return None, None

    global nid
    d = {'type': 'file', 'name': line['file_sha2'], 'fileType': line['file_type']}
    if line['reputation_score'] == 'NULL':
        d['score'] = str(0)
    else:
        d['score'] = line['reputation_score']
    if line['filename'] != 'NULL':
        d['data'] = line['filename']
    else:
        d['data'] = line['file_sha2']
    if line['prevalence'] != 'NULL':
        d['prevalence'] = line['prevalence']
    else:
        d['prevalence'] = -1

    if line['filesize'] != 'NULL':
        d['size'] = line['filesize']
    else:
        d['size'] = -1

    d['status'] = 0
    d['event'] = [line['event']]

    # Note that insert_method wil block repeated insertion, hence this line
    if line['file_sha2'] in name2id:
        return name2id[line['file_sha2']], d

    nid += 1
    name2id[line['file_sha2']] = str(nid)
    return str(nid), d


def get_url_node(line, k='url'):
    if line[k] == 'NULL':
        return None, None

    global nid
    d = {'type': 'url'}

    # Uncomment below line if you want 'referrer_url' as a node type
    # d['type'] = 'url' if k == 'parent_url' else k

    scheme, hostname, path, port = process_url(line[k])

    # Removes url parameters
    if line[k].find('?') == -1:
        data = line[k]
    else:
        data = line[k][:line[k].find('?')]
    d['name'] = data

    if hostname:
        d['data'] = hostname
    else:
        d['data'] = data
    d['score'] = str(0)
    d['prevalence'] = -1
    d['size'] = -1
    d['status'] = 1
    d['event'] = [line['event']]

    if data in name2id:
        return name2id[data], d
    nid += 1
    name2id[data] = str(nid)
    return str(nid), d


def get_fqdn_node(line, k='url'):
    global nid

    if line[k] == 'NULL':
        return None, None

    scheme, hostname, path, port = process_url(line[k])

    if hostname is None:
        return None, None

    d = {'data': hostname, 'score': str(0), 'name': hostname, 'prevalence': -1, 'size': -1, 'status': 1, 'event': []}

    # Separate IPs from FQDNs (IPv4 and IPv6) that may be contained in url
    if set(hostname).intersection(set('qwertyuiopasdfghjklzxcvbnm')) == set() \
            or ':' in hostname:
        d['type'] = 'ip'
    else:
        d['type'] = 'fqdn'

    if hostname in name2id:
        return name2id[hostname], d

    nid += 1
    name2id[hostname] = str(nid)
    return str(nid), d


def get_ip_node(line):
    if line['download_ip'] == 'NULL':
        return None, None

    global nid

    d = {'type': 'ip', 'data': line['download_ip'], 'score': str(0), 'name': line['download_ip'], 'prevalence': -1,
         'size': -1, 'status': 1, 'event': [line['event']]}

    if line['download_ip'] in name2id:
        return name2id[line['download_ip']], d

    nid += 1
    name2id[line['download_ip']] = str(nid)

    return str(nid), d


def rewrite_node_values(g, node_id, d):
    if g.node[node_id]['event']:
        g.node[node_id]['event'].extend(d['event'])

    if d['type'] == 'file' and g.node[node_id]['type'] == 'file' \
            and (int(d['prevalence']) > int(g.node[node_id]['prevalence'])
                 or int(d['size']) > int(g.node[node_id]['size'])
                 or g.node[node_id]['name'] == 'parent'):
        for attr in node_attributes:
            g.node[node_id][attr] = d[attr]


def insert_node(g, node_id, d):
    if node_id not in g:
        g.add_node(node_id)
        for key in d:
            g.node[node_id][key] = d[key]
    else:
        # update
        rewrite_node_values(g, node_id, d)

    # if event_id != None:
    # add_node_event_pairing(id, event_id)


'''
five types of edges:
1. f2f - file to file
2. l2f - link to file
3. l2l - link to link
4. ip2l - ip to link
5. d2l - FQ domain to link
'''


def insert_edge(g, src, trg, type='f2f', weighted=False):
    if weighted:
        # Weight edge by no. of download events for which node pairing exists
        try:
            g.edge[src][trg]['weight'] += 1
        except KeyError:
            g.add_edge(src, trg, type=type, weight=1)
        update_node_drops(g, src, trg)
    else:
        try:
            g.edge[src][trg]['weight']
        except KeyError:
            g.add_edge(src, trg, type=type, weight=0)


def update_node_drops(g, src, trg):
    # Increment 'dropper' (parent) for src
    try:
        g.node[src]['dropper'] += 1
    except KeyError:
        g.node[src]['dropper'] = 1

    # Increment 'droppee' (child) for trg
    try:
        g.node[trg]['droppee'] += 1
    except KeyError:
        g.node[trg]['droppee'] = 1


def build_mdn(g, line, include_fqdn=True):
    # Add mapping for event ID to timestamp
    event2timestamp[line['event']] = line['server_ts']

    # Build graph with nodes and edges
    f_id, f_d = get_file_node(line)
    p_id, p_d = get_parent_file_node(line)
    if f_id:
        insert_node(g, f_id, f_d)  # file node
    if p_id:
        insert_node(g, p_id, p_d)  # parent file node
    if f_id and p_id:
        insert_edge(g, p_id, f_id, type='f2f', weighted=True)

    if f_id:
        rurl_id, rurl_d = get_url_node(line, k='referrer_url')
        url_id, url_d = get_url_node(line, k='url')
        ip_id, ip_d = get_ip_node(line)

        # Remove IPs and hosts with disallowed IPs
        if ip_id and IP_in_subnet(ip_d['name'], disqualified_IPs):
            ip_id = None
            ip_d = None
        if url_id and IP_in_subnet(url_d['data'], disqualified_IPs):
            url_id = None
            url_d = None
        if rurl_id and IP_in_subnet(rurl_d['data'], disqualified_IPs):
            rurl_id = None
            rurl_d = None

        if rurl_id:
            insert_node(g, rurl_id, rurl_d)  # referrer url
        if url_id:
            insert_node(g, url_id, url_d)  # url
        if ip_id:
            insert_node(g, ip_id, ip_d)  # ip

        if rurl_id:
            insert_edge(g, rurl_id, f_id, type='l2f', weighted=True)  # file ---- referrer

        if rurl_id is None and url_id:
            insert_edge(g, url_id, f_id, type='l2f', weighted=True)  # file ---- url

        if rurl_id is None and url_id is None and ip_id:
            insert_edge(g, ip_id, f_id, type='l2f', weighted=True)  # file ---- ip

        if url_id and rurl_id:
            insert_edge(g, url_id, rurl_id, type='l2l', weighted=True)  # url ----- referrer

        if ip_id and url_id:
            insert_edge(g, ip_id, url_id, type='ip2l', weighted=True)  # ip ----- url

        # Assuming no host url, then link IP to landing page
        if rurl_id and url_id is None and ip_id:
            insert_edge(g, ip_id, rurl_id, type='ip2l', weighted=True)  # ip ---- referrer

        if include_fqdn:
            rfqdn_id, rfqdn_d = get_fqdn_node(line, k='referrer_url')
            fqdn_id, fqdn_d = get_fqdn_node(line, k='url')

            if rfqdn_id:
                insert_node(g, rfqdn_id, rfqdn_d)  # referrer FQDN
            if fqdn_id:
                insert_node(g, fqdn_id, fqdn_d)  # host FQDN

            if rfqdn_id and rurl_id:
                if rfqdn_d['type'] == 'ip':
                    insert_edge(g, rfqdn_id, rurl_id, type='ip2l', weighted=True)
                else:
                    insert_edge(g, rfqdn_id, rurl_id, type='d2l', weighted=True)  # referrer FQDN --- referrer
            if fqdn_id and url_id:
                if fqdn_d['type'] == 'ip':
                    insert_edge(g, fqdn_id, url_id, type='ip2l', weighted=True)
                else:
                    insert_edge(g, fqdn_id, url_id, type='d2l', weighted=True)  # FQDN --- url

    if p_id:
        url_id, url_d = get_url_node(line, k='parent_url')

        # Remove IPs and hosts with disallowed IPs
        if url_id and IP_in_subnet(url_d['data'], disqualified_IPs):
            url_id = None
            url_d = None

        if url_id:
            insert_node(g, url_id, url_d)
            insert_edge(g, url_id, p_id, type='l2f')

        if include_fqdn:
            fqdn_id, fqdn_d = get_fqdn_node(line, k='parent_url')

            if fqdn_id:
                insert_node(g, fqdn_id, fqdn_d)  # FQDN

            if fqdn_id and url_id:
                if fqdn_d['type'] == 'ip':
                    insert_edge(g, fqdn_id, url_id, type='ip2l')
                else:
                    insert_edge(g, fqdn_id, url_id, type='d2l')  # FQDN --- url


def benign_vs_malicious(g):
    benign = 0
    malicious = 0
    gray = 0
    for node in g.nodes():
        if float(g.node[node]['score']) <= -50:
            malicious += 1
        elif float(g.node[node]['score']) > 50:
            benign += 1
        elif float(g.node[node]['score']) != 0:
            gray += 1
    return benign, gray, malicious


def serialize_event_attr(g):
    """
    Transforms 'events' and 'eventToTimestamp' attributes so NX graph to be writable as GML
    :param g: networkX graph object
    :returns g
    """
    # Serialize 'events' attribute for each graph node
    for node_id in g.nodes():
        g.node[node_id]['event'] = json.dumps(g.node[node_id]['event'])

    return g


def deserialize_event_attr(G):
    """
    Transforms 'events' and 'eventToTimestamp' attributes in serialized igraph data to a usable format
    :param G: igraph graph object
    :returns G
    """

    # Deserialize 'events' attribute for each node
    for v in G.vs:
        v['event'] = json.loads(v['event'])

    G['event2timestamp'] = event2timestamp

    return G


def build(raw_data):
    g = nx.DiGraph()

    mypar = pyprind.ProgBar(int(subprocess.check_output(['wc', '-l', raw_data]).decode('utf8').split()[0]),
                            bar_char='=')

    with open(raw_data, 'r') as f:
        event = 0
        for line in f:
            line = line.rstrip()
            values = line.split('\t')
            values.append(event)
            if len(values) == len(data_fields):
                build_mdn(g, dict(zip(data_fields, values)))
            event += 1
            mypar.update()

    g = serialize_event_attr(g)

    return g


def build_graph_by_igraph(raw_data, loc, gml_filename):
    if not os.path.exists(loc):
        try:
            os.makedirs(loc)
        except Exception as e:
            pass

    g = build(raw_data)
    nx.write_gml(g, os.path.join(loc, gml_filename))
    G = Graph.Read_GML(os.path.join(loc, gml_filename))

    # Add event information
    G = deserialize_event_attr(G)

    # Add event to node lookup table
    G['event2nodes'] = {}
    for v in G.vs:
        for event in v['event']:
            try:
                G['event2nodes'][event].append(v.index)
            except:
                G['event2nodes'][event] = [v.index]

    return G
