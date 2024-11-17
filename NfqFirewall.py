from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw
import re

def load_rules(file_path):
    rules = []
    with open(file_path, 'r') as file:
        for line in file:
            rules.append(line.strip())
    return rules

def analyze_http_packet(packet):
    try:
        ip_layer = IP(packet)
        if ip_layer.haslayer(TCP):
            tcp_layer = ip_layer[TCP]
            if tcp_layer.sport == 80 or tcp_layer.dport == 80:
                if tcp_layer.haslayer(Raw):
                    http_layer = tcp_layer[Raw].load.decode('utf-8', errors='ignore')
                    return http_layer
    except Exception as e:
        print(f'Error analyzing packet: {e}')
        return None

def check_packet(packet, rules):
    in_rule = False, ""
    default_allow = True
    http = analyze_http_packet(packet)
    if http:
        for rule in rules:
            if (rule == "ALLOW"):
                defalut_allow = False
                continue
            elif (rule == "DROP"):
                defalut_allow = True
                continue
            if re.search(rule, http):
                in_rule = True, rule

    check, reason = in_rule
    chech = check ^ default_allow
    if (not check and reason == ""):
        reason = "Default strategy"
    return check ^ default_allow, reason

def callback(packet):
    data = packet.get_payload()

    if not analyze_http_packet(data):
        packet.accept()
        return

    verdict = ""
    check, rule = check_packet(data, rules)
    if check:
        packet.accept()
        verdict = "accepted"
    else:
        packet.drop()
        verdict = "dropped"

    reason = ""
    if (rule != ""):
        reason = f" with rule {rule}"
    print(f'Verdict: \'{verdict}{reason}\'.')

rules = load_rules('http_rules.txt')

nfqueue = NetfilterQueue()
nfqueue.bind(5, callback)

try:
    nfqueue.run()
except KeyboardInterrupt:
    print('Exiting...')

nfqueue.unbind()
