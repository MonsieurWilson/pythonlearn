# coding: utf-8
# __author__ = "Wilson Lan"

import os
import sys
import fcntl
import struct
import socket
import argparse
import time
import random
import array
from ctypes import Structure, c_ubyte, c_ushort, c_uint


IP_HEADER_LEN = 5
IPV4_HEADER_LEN_BYTES = 20
IPV4_VERSION = 4
IPV4_PACKET_ID = os.getpid()
IPV4_TTL = 64
IPV4_TOS = 0
IPV4_IHL_VER = (IPV4_VERSION << 4) + IP_HEADER_LEN

MPLS_S = 1
MPLS_EXP = 1
MPLS_TTL = 64

ICMP_TYPE = 8
ICMP_CODE = 0

class ETHHEADER(Structure):
    _fields_ = [
        ('dmac0', c_ubyte),
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

class MPLSHEADER(Structure):
    _fields_ = [
        ('mpls_label', c_uint),
        ('mpls_exp', c_ubyte),
        ('mpls_s', c_ubyte),
        ('mpls_ttl', c_ubyte)]

    header_size = 4

    def build(self):
        return struct.pack('!I',
                    (((((self.mpls_label << 3) + self.mpls_exp) << 1) + self.mpls_s) << 8) + self.mpls_ttl)

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
        ip_header_pack = struct.pack('!B B H H H B B H I I', IPV4_IHL_VER, self.ip_tos, self.ip_tot_len, self.ip_id,
                                     self.ip_frag_offset, self.ip_ttl, self.ip_proto, self.ip_chksum, self.ip_saddr,
                                     self.ip_daddr)
        return ip_header_pack

    def set_ip_checksum(self, checksum):
        self.ip_chksum = checksum

class ICMPHEADER(Structure):
    _fields_ = [
        ('icmp_type', c_ubyte),
        ('icmp_code', c_ubyte),
        ('icmp_chksum', c_ushort),
        ('icmp_id', c_ushort),
        ('icmp_seq', c_ushort)]

    header_size = 8

    def build(self):
        return struct.pack('!B B H H H', self.icmp_type, self.icmp_code, self.icmp_chksum, self.icmp_id, self.icmp_seq)

    def set_icmp_checksum(self, checksum):
        self.icmp_chksum = checksum

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

def decode_mpls(payload, mpls_header_values):
    mpls_header = payload[ETHHEADER.header_size: ETHHEADER.header_size+MPLSHEADER.header_size]

    _header_values = struct.unpack('!I B B B', mpls_header)
    mpls_header_values.mpls_label = _header_values[0] >> 12
    mpls_header_values.mpls_exp   = _header_values[1] >> 5
    mpls_header_values.mpls_s     = _header_values[2] >> 7
    mpls_header_values.mpls_ttl   = _header_values[3]

def decode_ip(payload, ip_header_values):
    ip_header = payload[ETHHEADER.header_size+MPLSHEADER.header_size: \
            ETHHEADER.header_size+MPLSHEADER.header_size+IP4HEADER.header_size]

    _header_values = struct.unpack('!B B H H H B B H I I', ip_header)
    ip_header_values.ip_ihl         = _header_values[0] & 0x0F
    ip_header_values.ip_ver         = _header_values[0] >> 4
    ip_header_values.ip_tos         = _header_values[1]
    ip_header_values.ip_tot_len     = _header_values[2]
    ip_header_values.ip_id          = _header_values[3]
    ip_header_values.ip_frag_offset = _header_values[4]
    ip_header_values.ip_ttl         = _header_values[5]
    ip_header_values.ip_proto       = _header_values[6]
    ip_header_values.ip_chksum      = _header_values[7]
    ip_header_values.ip_saddr       = _header_values[8]
    ip_header_values.ip_daddr       = _header_values[9]

def decode_icmp(payload, icmp_header_values):
    icmp_header = payload[ETHHEADER.header_size+MPLSHEADER.header_size+IP4HEADER.header_size: \
            ETHHEADER.header_size+MPLSHEADER.header_size+IP4HEADER.header_size+ICMPHEADER.header_size]

    _header_values = struct.unpack('!B B H H H', icmp_header)
    icmp_header_values.icmp_type   = _header_values[0]
    icmp_header_values.icmp_code   = _header_values[1]
    icmp_header_values.icmp_chksum = _header_values[2]
    icmp_header_values.icmp_id     = _header_values[3]
    icmp_header_values.icmp_seq    = _header_values[4]

def build_eth_header(src_macaddr, dst_macaddr, eth_type):
    eth_header = ETHHEADER()

    src_mac_addr = src_macaddr.split(":")
    dst_mac_addr = dst_macaddr.split(":")

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

    eth_header.ethertype0 = int(eth_type[2: 4], 16)
    eth_header.ethertype1 = int(eth_type[4:], 16)

    eth_header_pack = eth_header.build()

    return eth_header, eth_header_pack

def build_mpls_header(label, exp, s, ttl):
    mpls_header = MPLSHEADER(label, exp, s, ttl)
    mpls_header_pack = mpls_header.build()

    return mpls_header, mpls_header_pack

def build_ipv4_header(ip_tot_len, proto, src_ip, dest_ip, swap_ip):
    if src_ip:
        ip_saddr = socket.inet_aton(src_ip)
    else:
        ip_saddr = socket.inet_aton(socket.gethostbyname(socket.gethostname()))

    if swap_ip == True:
        new_ip_daddr = int_from_bytes(ip_saddr)
        new_ip_saddr = socket.inet_aton(dest_ip)
        new_ip_saddr = int_from_bytes(new_ip_saddr)
    else:
        new_ip_saddr = int_from_bytes(ip_saddr)
        new_ip_daddr = int_from_bytes(socket.inet_aton(dest_ip))

    ip_header = IP4HEADER(IP_HEADER_LEN,
                          IPV4_VERSION,
                          IPV4_TOS,
                          ip_tot_len,
                          IPV4_PACKET_ID,
                          0,
                          IPV4_TTL,
                          proto,
                          0,
                          new_ip_saddr,
                          new_ip_daddr)

    checksum = compute_internet_checksum(ip_header.build())
    ip_header.set_ip_checksum(checksum)
    ip_header_pack = ip_header.build()

    return ip_header, ip_header_pack

def build_icmp_header(icmp_type, icmp_code, icmp_id, icmp_seq, icmp_payload):
    icmp_header = ICMPHEADER(icmp_type, icmp_code, 0, icmp_id, icmp_seq)
    checksum = compute_internet_checksum(icmp_header.build()+icmp_payload)
    icmp_header.set_icmp_checksum(checksum)
    icmp_header_pack = icmp_header.build()

    return icmp_header, icmp_header_pack

def build_send_packet(src_macaddr, dst_macaddr, eth_type, src_ipaddr, dst_ipaddr, payload, packet_count, verbose):
    eth_header, eth_header_pack = build_eth_header(src_macaddr, dst_macaddr, eth_type)

    mpls_header, mpls_header_pack = build_mpls_header(os.getpid(),
                                                      MPLS_EXP,
                                                      MPLS_S,
                                                      MPLS_TTL)

    ip_header, ip_header_pack = build_ipv4_header(len(payload)+IP4HEADER.header_size+ICMPHEADER.header_size,
                                                  socket.IPPROTO_ICMP,
                                                  src_ipaddr,
                                                  dst_ipaddr,
                                                  False)

    icmp_header, icmp_header_pack = build_icmp_header(ICMP_TYPE,
                                                      ICMP_CODE,
                                                      os.getpid(),
                                                      packet_count,
                                                      payload)

    if verbose == "on":
        print_eth_header(eth_header)
        print_mpls_header(mpls_header)
        print_ip4_header(ip_header)
        print_icmp_header(icmp_header)
        print "=" * 80

    return eth_header_pack + mpls_header_pack + ip_header_pack + icmp_header_pack + payload

def int_from_bytes(s):
    return sum(ord(c) << (i * 8) for i, c in enumerate(s[::-1]))

def compute_internet_checksum(data):
    checksum = 0
    n = len(data) % 2
    # data padding
    pad = bytearray('', encoding='UTF-8')
    if n == 1:
        pad = bytearray(b'\x00')
    # for i in range(0, len(data + pad) - n, 2):
    for i in range(0, len(data)-1, 2):
        checksum += (ord(data[i]) << 8) + (ord(data[i+1]))
    if n == 1:
        checksum += (ord(data[len(data)-1]) << 8) + (pad[0])
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = ~checksum & 0xFFFF
    return checksum

def print_eth_header(eth_header):
    print "Eth Dst MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x, Src MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x, Ethertype: 0x%.4x" % (eth_header.dmac0, eth_header.dmac1, eth_header.dmac2, eth_header.dmac3, eth_header.dmac4, eth_header.dmac5, eth_header.smac0, eth_header.smac1, eth_header.smac2, eth_header.smac3, eth_header.smac4, eth_header.smac5, (eth_header.ethertype0<<8) | eth_header.ethertype1)

def print_mpls_header(mpls_header):
    print "MPLS Label: %s, Exp: %s, S: %s, TTL: %s" % (mpls_header.mpls_label, mpls_header.mpls_exp, mpls_header.mpls_s, mpls_header.mpls_ttl)

def print_ip4_header(ip_header):
    print "IP Version: %s IP Header Length: %s, TTL: %s, Protocol: %s, Src IP: %s, Dst IP: %s" % (ip_header.ip_ver, ip_header.ip_ihl, ip_header.ip_ttl, ip_header.ip_proto, str(socket.inet_ntoa(struct.pack('!I', ip_header.ip_saddr))), str(socket.inet_ntoa(struct.pack('!I', ip_header.ip_daddr))))

def print_icmp_header(icmp_header):
    print "ICMP ID: %s, Seq: %s, CheckSum: %s" % (icmp_header.icmp_id, icmp_header.icmp_seq, icmp_header.icmp_chksum)

def main():
    parse = argparse.ArgumentParser(description="This is an packet forward tool, you can use it to forward packets.", prog="send.py")
    parse.add_argument("-i", "--interface",
            help="Specify the interface to send mpls frames")
    parse.add_argument("-v", "--verbose",
            help="Get some detail information", default="off")
    parse.add_argument("--src-ipaddr",
            help="Specify the source IP adress", default=None)
    parse.add_argument("--dst-ipaddr",
            help="Specify the destination IP adress", default=None)
    parse.add_argument("--src-macaddr",
            help="Specify the source MAC address", default=None)
    parse.add_argument("--dst-macaddr",
            help="Specify the destination MAC address", default=None)
    parse.add_argument("--eth-type",
            help="Send unicast or multicast frames, default to be unicast", default="unicast")
    args = parse.parse_args()

    if args.eth_type == "unicast":
        eth_type = "0x8847"
    else:
        eth_type = "0x8848"

    send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(int(eth_type, 16)))
    packet_count = 0
    payload = struct.pack("d", time.time())

    while True:
        send_packet = build_send_packet(args.src_macaddr,
                                        args.dst_macaddr,
                                        eth_type,
                                        args.src_ipaddr,
                                        args.dst_ipaddr,
                                        payload,
                                        packet_count,
                                        args.verbose)

        send_socket.bind((args.interface, 0))
        send_socket.send(send_packet)

        packet_count += 1
        time.sleep(1)


if __name__ == "__main__":
    main()
