import socket
import struct
import os
from scapy.all import *
import threading

def create_raw_socket(interface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0))
    return sock

def read_rules(file_path):
    rules = []
    with open(file_path, 'r') as file:
        for line in file:
            rules.append(line.strip())
    return rules

def filter_packet(packet, rules):
    eth = Ether(packet)
    if eth.haslayer(IP):
        ip = eth[IP]
        if ip.haslayer(TCP):
            tcp = ip[TCP]
            src_ip = ip.src
            dst_ip = ip.dst
            proto = 'TCP'
            src_port = tcp.sport
            dst_port = tcp.dport
        elif ip.haslayer(UDP):
            udp = ip[UDP]
            src_ip = ip.src
            dst_ip = ip.dst
            proto = 'UDP'
            src_port = udp.sport
            dst_port = udp.dport
        elif ip.haslayer(ICMP):
            src_ip = ip.src
            dst_ip = ip.dst
            proto = 'ICMP'
            src_port = None
            dst_port = None
        else:
            return True
    else:
        return True

    drop = True
    in_rule = False
    for rule in rules:
        if rule == 'ALLOW':
            drop = False
            continue
        elif rule == 'DROP':
            drop = True
            continue

        if rule.startswith('src_ip='):
            if src_ip == rule.split('=')[1]:
                in_rule = True
        if rule.startswith('dst_ip='):
            if dst_ip == rule.split('=')[1]:
                in_rule = True
        if rule.startswith('proto='):
            if proto == rule.split('=')[1]:
                in_rule = True
        if rule.startswith('src_port=') and src_port != None:
            if src_port == int(rule.split('=')[1]):
                in_rule = True
        elif rule.startswith('dst_port=') and dst_port != None:
            if dst_port == int(rule.split('=')[1]):
                in_rule = True

    return in_rule ^ drop

def forward_packet(packet, dest_socket, verbose=0):
    dest_socket.send(packet)
    if (verbose != 0):
        print(f'Packet {Ether(packet)} was accepted.')

def process_iface(socket, dest_socket, rules):
    while True:
        packet, addr = socket.recvfrom(65535)
        if (filter_packet(packet, rules)):
            forward_packet(packet, dest_socket, verbose=1)
        else:
            print(f'Packet {Ether(packet)} was dropped.')

interface1 = 'eth0'
interface2 = 'eth1'
rules_file = 'rules.txt'

sock1 = create_raw_socket(interface1)
sock2 = create_raw_socket(interface2)

rules = read_rules(rules_file)

thread1 = threading.Thread(target=process_iface, args=(sock1, sock2, rules))
thread2 = threading.Thread(target=process_iface, args=(sock2, sock1, rules))

thread1.start()
thread2.start()

thread1.join()
thread2.join()
