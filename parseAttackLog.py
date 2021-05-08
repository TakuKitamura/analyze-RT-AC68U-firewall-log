import re
import csv
import sys


def sanitize(s):
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace('\'', '&#39;')


tcp_port_and_count = {}
udp_port_and_count = {}

argv = sys.argv
argc = len(sys.argv)

if argc != 2:
    print('usage: python3 parseAttackLog.py filewall.log')
    exit(1)

with open(argv[1]) as f:
    for l in f.readlines():
        if 'DROP' not in l:
            continue
        if 'PROTO=TCP' in l:
            port_and_count = tcp_port_and_count
        elif 'PROTO=UDP' in l:
            port_and_count = udp_port_and_count
        else:
            continue

        rep = re.compile(r'DPT=\d*')
        start, end = rep.search(l).span()

        port = int(l[start+4:end])

        if port in port_and_count.keys():
            port_and_count[port] += 1
        else:
            port_and_count[port] = 1

# https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
with open('./service-names-port-numbers.csv', newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    csv_data = list(reader)

html = '<style>table, td{border: 1px solid #333; margin: 20px;}thead, tfoot{background-color: #333; color: #fff;}.flex{display: flex;}</style><div class="flex">'

for proto in ['TCP', 'UDP']:
    tcp_or_udp_result = {}
    if proto == 'TCP':
        tcp_or_udp_result = tcp_port_and_count
    elif proto == 'UDP':
        tcp_or_udp_result = udp_port_and_count
    else:
        print('error: unknown proto')
        continue

    graph_base = sorted(tcp_or_udp_result.items(),
                        reverse=True, key=lambda x: x[1])  # Count Sort

    insert_table = ''
    for v in graph_base:
        service = 'unknown'
        descript = 'unknown'
        port, count = v

        for row in csv_data:
            read_port_number = -1

            try:
                read_port_number = int(row['Port Number'])
            except:
                pass

            if port == read_port_number and proto.lower() == row['Transport Protocol'].lower():

                service = sanitize(row['Service Name'])
                port = sanitize(row['Port Number'])
                proto = sanitize(row['Transport Protocol'].upper())
                descript = sanitize(row['Description'])

        insert_table += '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
            service, port, descript, count)

    html += '<table><thead><tr><th colspan=4>{}</th></thead><tbody><tr><td>Service</td><td>Port</td><td>Description</td><td>Count</td></tr>{}</tbody></table>'.format(
        proto, insert_table)

html += '</div>'
with open('index.html', mode='w') as f:
    f.write(html)
