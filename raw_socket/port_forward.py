#!/usr/bin/env python
# coding: utf-8
# __author__ = "Wilson Lan"

import os
import sys
import fcntl
import struct
import socket
import argparse
import time
from ctypes import Structure, c_ubyte, c_ushort, c_uint


class ETHHEADER(Structure):
    _fields_ = [('dmac0', c_ubyte),
                ('dmac1', c_ubyte),
                ('dmac2', c_ubyte),
                ('dmac3', c_ubyte),
                ('dmac4', c_ubyte),
                ('dmac5', c_ubyte),
                ('smac0', c_ubyte),
                ('smac1', c_ubyte),
                ('smac2', c_ubyte),
                ('smac3', c_ubyte),
                ('smac4', c_ubyte),
                ('smac5', c_ubyte),
                ('ethertype0', c_ubyte),
                ('ethertype1', c_ubyte)]

    header_size = 14

    def build(self):
        return struct.pack('!B B B B B B B B B B B B B B',
                    self.dmac0,
                    self.dmac1,
                    self.dmac2,
                    self.dmac3,
                    self.dmac4,
                    self.dmac5,
                    self.smac0,
                    self.smac1,
                    self.smac2,
                    self.smac3,
                    self.smac4,
                    self.smac5,
                    self.ethertype0,
                    self.ethertype1)

    def get_src_macaddr(self):
        return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
                    self.smac0,
                    self.smac1,
                    self.smac2,
                    self.smac3,
                    self.smac4,
                    self.smac5)

    def get_dst_macaddr(self):
        return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
                    self.dmac0,
                    self.dmac1,
                    self.dmac2,
                    self.dmac3,
                    self.dmac4,
                    self.dmac5)

    def get_ethertype(self):
        return "0x%.4x" % ((self.ethertype0<<8) | self.ethertype1)


class IP4HEADER(Structure):
    _fields_ = [
        ('ip_ihl', c_ubyte),
        ('ip_ver', c_ubyte),
        ('ip_tos', c_ubyte),
        ('ip_tot_len', c_ushort),
        ('ip_id', c_ushort),
        ('ip_frag_offset', c_ushort),
        ('ip_ttl', c_ubyte),
        ('ip_proto', c_ubyte),
        ('ip_chksum', c_ushort),
        ('ip_saddr', c_uint),
        ('ip_daddr', c_uint)]

    header_size = 20

    def build(self):
        ip_ihl_ver = self.ip_ihl + (self.ip_ver << 4)
        ip_header_pack = struct.pack('!B B H H H B B H I I', ip_ihl_ver, self.ip_tos, self.ip_tot_len, self.ip_id,
                                  self.ip_frag_offset, self.ip_ttl, self.ip_proto, self.ip_chksum, self.ip_saddr,
                                  self.ip_daddr)
        return ip_header_pack

    def set_ip_checksum(self, checksum):
        self.ip_chksum = checksum

    def get_src_ipaddr(self):
        return str(socket.inet_ntoa(struct.pack('!I', self.ip_saddr)))

    def get_dst_ipaddr(self):
        return str(socket.inet_ntoa(struct.pack('!I', self.ip_daddr)))


def decode_eth(payload, eth_header_values):
    eth_header = payload[0: ETHHEADER.header_size]

    _header_values = struct.unpack('!B B B B B B B B B B B B B B', eth_header)
    eth_header_values.dmac0 = _header_values[0]
    eth_header_values.dmac1 = _header_values[1]
    eth_header_values.dmac2 = _header_values[2]
    eth_header_values.dmac3 = _header_values[3]
    eth_header_values.dmac4 = _header_values[4]
    eth_header_values.dmac5 = _header_values[5]
    eth_header_values.smac0 = _header_values[6]
    eth_header_values.smac1 = _header_values[7]
    eth_header_values.smac2 = _header_values[8]
    eth_header_values.smac3 = _header_values[9]
    eth_header_values.smac4 = _header_values[10]
    eth_header_values.smac5 = _header_values[11]
    eth_header_values.ethertype0 = _header_values[12]
    eth_header_values.ethertype1 = _header_values[13]

def decode_ip(payload, ip_header_values):
    ip_header = payload[ETHHEADER.header_size: ETHHEADER.header_size+IP4HEADER.header_size]

    _header_values = struct.unpack('!B B H H H B B H I I', ip_header)
    ip_header_values.ip_ihl = _header_values[0] & 0x0F
    ip_header_values.ip_ver = _header_values[0] >> 4
    ip_header_values.ip_tos = _header_values[1]
    ip_header_values.ip_tot_len = _header_values[2]
    ip_header_values.ip_id = _header_values[3]
    ip_header_values.ip_frag_offset = _header_values[4]
    ip_header_values.ip_ttl = _header_values[5]
    ip_header_values.ip_proto = _header_values[6]
    ip_header_values.ip_chksum = _header_values[7]
    ip_header_values.ip_saddr = _header_values[8]
    ip_header_values.ip_daddr = _header_values[9]

def build_eth_header(request_eth_header, src_macaddr, dst_macaddr, outer_interface, swap_mac):
    eth_header = ETHHEADER()

    try:
        # If doesn't specify the source MAC address,
        # using the MAC address of outer interface.
        if src_macaddr:
            src_mac_addr = src_macaddr.split(":")
        else:
            src_mac_addr = getmac(outer_interface).split(":")
            # src_mac_addr = request_eth_header.get_src_macaddr(":")

        # If doesn't specify the destination MAC address,
        # using the MAC address of original ethernet frame.
        if dst_macaddr:
            dst_mac_addr = dst_macaddr.split(":")
        else:
            dst_mac_addr = request_eth_header.get_dst_macaddr().split(":")

        if swap_mac:
            src_mac_addr, dst_mac_addr = dst_mac_addr, src_mac_addr

        eth_header.smac0 = int(src_mac_addr[0], 16)
        eth_header.smac1 = int(src_mac_addr[1], 16)
        eth_header.smac2 = int(src_mac_addr[2], 16)
        eth_header.smac3 = int(src_mac_addr[3], 16)
        eth_header.smac4 = int(src_mac_addr[4], 16)
        eth_header.smac5 = int(src_mac_addr[5], 16)

        eth_header.dmac0 = int(dst_mac_addr[0], 16) 
        eth_header.dmac1 = int(dst_mac_addr[1], 16) 
        eth_header.dmac2 = int(dst_mac_addr[2], 16) 
        eth_header.dmac3 = int(dst_mac_addr[3], 16) 
        eth_header.dmac4 = int(dst_mac_addr[4], 16) 
        eth_header.dmac5 = int(dst_mac_addr[5], 16) 

        eth_header.ethertype0 = request_eth_header.ethertype0
        eth_header.ethertype1 = request_eth_header.ethertype1

    except Exception, e:
        print "Parse mac failed: %s" % e

    return eth_header, eth_header.build()


def build_ip4_header(request_ip4_header, src_ipaddr, dst_ipaddr, payload, swap_ip):
    try:
        # If doesn't specify the source IP address,
        # using the source MAC address of original IP packet.
        if src_ipaddr:
            src_ip_addr = src_ip_addr
        else:
            src_ip_addr = request_ip4_header.get_src_ipaddr()

        # If doesn't specify the destination IP address,
        # using the destination MAC address of original IP packet.
        if dst_ipaddr:
            dst_ip_addr = dst_ipaddr
        else:
            dst_ip_addr = request_ip4_header.get_dst_ipaddr()
    except Exception, e:
        print "Parse ip failed: %s" % e

    if swap_ip:
        src_ip_addr, dst_ip_addr = dst_ip_addr, src_ip_addr

    new_ip_saddr = int_from_bytes(socket.inet_aton(src_ip_addr))
    new_ip_daddr = int_from_bytes(socket.inet_aton(dst_ip_addr))
    
    ip_header = IP4HEADER(request_ip4_header.ip_ihl,
                          request_ip4_header.ip_ver,
                          request_ip4_header.ip_tos,
                          len(payload)+IP4HEADER.header_size,
                          request_ip4_header.ip_id,
                          request_ip4_header.ip_frag_offset,
                          request_ip4_header.ip_ttl-1,
                          request_ip4_header.ip_proto,
                          0,
                          new_ip_saddr,
                          new_ip_daddr)

    checksum = compute_internet_checksum(ip_header.build())
    ip_header.set_ip_checksum(checksum)
    ip_header_pack = ip_header.build()

    return ip_header, ip_header_pack

def build_forward_request_packet(outer_interface, request_eth_header, request_ip4_header, payload, src_ipaddr, dst_ipaddr, src_macaddr, dst_macaddr):
    # Build ethernet header
    forward_eth_header, forward_eth_header_pack = \
                        build_eth_header(request_eth_header,
                                         src_macaddr,
                                         dst_macaddr,
                                         outer_interface,
                                         False)

    # Build IPv4 header
    forward_ip_header, forward_ip_header_pack = \
                        build_ip4_header(request_ip4_header, 
                                         src_ipaddr, 
                                         dst_ipaddr, 
                                         payload,
                                         False)

    return forward_eth_header_pack + forward_ip_header_pack + payload

def getmac(interface):
    try:
        mac = open('/sys/class/net/'+interface+'/address').readline().strip()
    except:
        mac = None

    return mac

def int_from_bytes(s):
    return sum(ord(c) << (i * 8) for i, c in enumerate(s[::-1]))

def compute_internet_checksum(data):
    checksum = 0
    n = len(data) % 2

    pad = bytearray('', encoding='UTF-8')
    if n == 1:
        pad = bytearray(b'\x00')

    for i in range(0, len(data)-1, 2):
        checksum += (ord(data[i]) << 8) + (ord(data[i + 1]))
    if n == 1:
        checksum += (ord(data[len(data)-1]) << 8) + (pad[0])
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = ~checksum & 0xffff

    return checksum

def print_eth_header(ethheader):
    print "Eth Dst MAC: %s, Src MAC: %s, Ethertype: %s" % (
            ethheader.get_dst_macaddr(), ethheader.get_src_macaddr(), ethheader.get_ethertype())

def print_ip4_header(ipheader):
    print "IP Version: %s IP Header Length: %s, TTL: %s, Protocol: %s, Src IP: %s, Dst IP: %s" % (
            ipheader.ip_ver, ipheader.ip_ihl, ipheader.ip_ttl, ipheader.ip_proto, ipheader.get_src_ipaddr(), ipheader.get_dst_ipaddr())

def main():
    parse = argparse.ArgumentParser(description="This is an packet forward tool, you can use it to forward packets.", prog="port_forward.py")
    parse.add_argument("-i", "--interface",
            help="Specify the interface to listen")
    parse.add_argument("-o", "--outer-interface",
            help="Specify the interface to do forwarding")
    parse.add_argument("-v", "--verbose",
            help="Get some detail information", default="off")
    parse.add_argument("--src-ipaddr",
            help="Specify the source IP adress", default=None)
    parse.add_argument("--dst-ipaddr",
            help="Specify the destination IP adress", default=None)
    parse.add_argument("--src-macaddr",
            help="Specify the MAC address of source machine", default=None)
    parse.add_argument("--dst-macaddr",
            help="Specify the MAC address of destination machine", default=None)

    args = parse.parse_args()

    if args.interface is None or args.outer_interface is None:
        print \
"""Error usage: you must give both the inner interface and outer interface for port forward.
Please use -i/--interface and -o/--outer-interface to specify seperately.
Refer to --help for more details."""
        sys.exit(-1)

    request_socket = forward_request_socket = socket.socket(socket.AF_PACKET,
                                                            socket.SOCK_RAW,
                                                            socket.ntohs(0x0800))

    packet_count = 0
    payload_offset = ETHHEADER.header_size + IP4HEADER.header_size

    while True:
        packet_count += 1

        request_socket.bind((args.interface, 0))
        request_packet = request_socket.recvfrom(65535)[0]

        request_eth_header = ETHHEADER()
        decode_eth(request_packet, request_eth_header)

        request_ip4_header = IP4HEADER()
        decode_ip(request_packet, request_ip4_header)

        payload = request_packet[payload_offset:]

        if args.verbose == "on":
            print "Received #%d request packet:" % packet_count
            print_eth_header(request_eth_header)
            print_ip4_header(request_ip4_header)
        
        # forward request packet to destination
        forward_request_packet = build_forward_request_packet(args.outer_interface, 
                                                              request_eth_header, 
                                                              request_ip4_header, 
                                                              payload, 
                                                              args.src_ipaddr, 
                                                              args.dst_ipaddr, 
                                                              args.src_macaddr, 
                                                              args.dst_macaddr)
            
        if args.verbose == "on":
            forward_eth_header = ETHHEADER()
            decode_eth(forward_request_packet, forward_eth_header)
            forward_ip4_header = IP4HEADER()
            decode_ip(forward_request_packet, forward_ip4_header)

            print "Forward #%d request packet:" % packet_count
            print_eth_header(forward_eth_header)
            print_ip4_header(forward_ip4_header)
            print "-" * 100

        forward_request_socket.bind((args.outer_interface, 0))
        forward_request_socket.send(forward_request_packet)

if __name__ == "__main__":
    main()
