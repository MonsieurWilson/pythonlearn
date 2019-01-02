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


ETH_TYPE = "0x0800"

IP_HEADER_LEN = 5
IPV4_VERSION = 4
IPV4_PACKET_ID = os.getpid()
IPV4_TTL = 64
IPV4_TOS = 0
IPV4_IHL_VER = (IPV4_VERSION << 4) + IP_HEADER_LEN

ICMP_TYPE = 8
ICMP_CODE = 0
ICMP_ID = os.getpid()

VXLAN_FLAGS = 0
VXLAN_RESERVED = 0
VXLAN_VNI = 0x0001
VXLAN_RESERVED2 = 0


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
        ('src_ipaddr', c_uint),
        ('dst_ipaddr', c_uint)]

    header_size = 20

    def build(self):
        ip_header_pack = struct.pack('!B B H H H B B H I I', IPV4_IHL_VER, self.ip_tos, self.ip_tot_len, self.ip_id,
                                     self.ip_frag_offset, self.ip_ttl, self.ip_proto, self.ip_chksum, self.src_ipaddr,
                                     self.dst_ipaddr)
        return ip_header_pack

    def set_ip_checksum(self, checksum):
        self.ip_chksum = checksum

    def get_src_ipaddr(self):
        return str(socket.inet_ntoa(struct.pack('!I', self.src_ipaddr)))

    def get_dst_ipaddr(self):
        return str(socket.inet_ntoa(struct.pack('!I', self.dst_ipaddr)))


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


class UDPHEADER(Structure):
    _fields_ = [
        ('udp_sport', c_ushort),
        ('udp_dport', c_ushort),
        ('udp_len', c_ushort),
        ('udp_chksum', c_ushort)]

    header_size = 8

    def build(self):
        udp_header_pack = struct.pack('!H H H H', self.udp_sport, self.udp_dport, self.udp_len, self.udp_chksum)
        return udp_header_pack

    def set_udp_checksum(self, checksum):
        self.udp_chksum = checksum


class PSEUDO_UDPHEADER(Structure):
    def __init__(self):
        self.src_ipaddr = 0
        self.dst_ipaddr = 0
        self.zeroes = 0
        self.proto = 17
        self.length = 0

    def build(self):
        pudp_header_pack = struct.pack('!I I B B H', self.src_ipaddr, self.dst_ipaddr, self.zeroes, self.proto, self.length)
        return pudp_header_pack


class VXLANHEADER(Structure):
    _fields_ = [
        ('flags', c_ubyte),
        ('reserved', c_uint, 24),
        ('vni', c_uint, 24),
        ('reserved2', c_uint, 8)]

    def __init__(self, flags=int('00001000', 2), reserved=0, vni=int('1' * 24, 2), reserved2=0, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.flags = flags
        self.reserved = reserved
        self.vni = vni
        self.reserved2 = reserved2

    header_size = 8

    def build(self):
        vxlan_header_pack = struct.pack('!I I', (self.flags << 24) + self.reserved, (self.vni <<8) + self.reserved2)
        return vxlan_header_pack

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
    ip_header = payload[ETHHEADER.header_size:
            ETHHEADER.header_size+IP4HEADER.header_size]

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
    ip_header_values.src_ipaddr     = _header_values[8]
    ip_header_values.dst_ipaddr     = _header_values[9]

def decode_icmp(payload, icmp_header_values):
    icmp_header = payload[ETHHEADER.header_size+IP4HEADER.header_size:
            ETHHEADER.header_size+IP4HEADER.header_size+ICMPHEADER.header_size]

    _header_values = struct.unpack('!B B H H H', icmp_header)
    icmp_header_values.icmp_type   = _header_values[0]
    icmp_header_values.icmp_code   = _header_values[1]
    icmp_header_values.icmp_chksum = _header_values[2]
    icmp_header_values.icmp_id     = _header_values[3]
    icmp_header_values.icmp_seq    = _header_values[4]

def decode_udp(payload, udp_header_values):
    udp_header = payload[ETHHEADER.header_size+IP4HEADER.header_size:
            ETHHEADER.header_size+IP4HEADER.header_size+UDPHEADER.header_size]

    _header_values = struct.unpack('!H H H H', udp_header)
    udp_header_values.udp_sport = _header_values[0]
    udp_header_values.udp_dport = _header_values[1]
    udp_header_values.udp_len   = _header_values[2]
    udp_header_values.udp_sum   = _header_values[3]

def decode_vxlan(payload, vxlan_header_values):
    vxlan_header = payload[ETHHEADER.header_size+IP4HEADER.header_size+UDPHEADER.header_size:
            ETHHEADER.header_size+IP4HEADER.header_size+UDPHEADER.header_size+VXLANHEADER.header_size]

    _header_values = struct.unpack('!I I', vxlan_header)
    vxlan_header_values.flags     = _header_values[0] >> 24
    vxlan_header_values.reserved  = _header_values[0] & 0xFFFFFF
    vxlan_header_values.vni       = _header_values[1] >> 8
    vxlan_header_values.reserved  = _header_values[1] & 0xFF


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

def build_ipv4_header(ip_tot_len, proto, src_ip, dst_ip, swap_ip):
    if src_ip:
        src_ipaddr = socket.inet_aton(src_ip)
    else:
        src_ipaddr = socket.inet_aton(socket.gethostbyname(socket.gethostname()))

    if swap_ip == True:
        new_dst_ipaddr = int_from_bytes(src_ipaddr)
        new_src_ipaddr = socket.inet_aton(dst_ip)
        new_src_ipaddr = int_from_bytes(new_src_ipaddr)
    else:
        new_src_ipaddr = int_from_bytes(src_ipaddr)
        new_dst_ipaddr = int_from_bytes(socket.inet_aton(dst_ip))

    ip_header = IP4HEADER(IP_HEADER_LEN,
                          IPV4_VERSION,
                          IPV4_TOS,
                          ip_tot_len,
                          IPV4_PACKET_ID,
                          0,
                          IPV4_TTL,
                          proto,
                          0,
                          new_src_ipaddr,
                          new_dst_ipaddr)

    checksum = compute_internet_checksum(ip_header.build())
    ip_header.set_ip_checksum(checksum)
    ip_header_pack = ip_header.build()

    return ip_header, ip_header_pack

def build_icmp_header(type, code, id, seq, payload):
    icmp_header = ICMPHEADER(type, code, 0, id, seq)
    checksum = compute_internet_checksum(icmp_header.build()+payload)
    icmp_header.set_icmp_checksum(checksum)
    icmp_header_pack = icmp_header.build()

    return icmp_header, icmp_header_pack

def build_udp_header(src_port, dst_port, ip_header, payload):
    udp_header = UDPHEADER(int(src_port),
                           int(dst_port),
                           UDPHEADER.header_size+len(payload),
                           0)

    # build pseudo header to calculate checksum
    pudp_header = PSEUDO_UDPHEADER()
    pudp_header.src_ipaddr = ip_header.src_ipaddr
    pudp_header.dst_ipaddr = ip_header.dst_ipaddr
    pudp_header.length     = udp_header.udp_len


    # the UDP checksum of VXLAN packet must be zero
    # udp_chksum = compute_internet_checksum(pudp_header.build() + udp_header.build() + payload)
    # udp_header.set_udp_checksum(udp_chksum)

    udp_header_pack = udp_header.build()

    return udp_header, udp_header_pack

def build_vxlan_header(flags, reserved, vni, reserved2):
    if flags != int('00001000', 2):
        flags = int('00001000', 2)
    vxlan_header = VXLANHEADER(flags, reserved, vni, reserved2)
    vxlan_header_pack = vxlan_header.build()

    return vxlan_header, vxlan_header_pack

def build_vxlan_packet(outer_src_macaddr, outer_dst_macaddr, outer_src_ipaddr, outer_dst_ipaddr,
                       inner_src_macaddr, inner_dst_macaddr, inner_src_ipaddr, inner_dst_ipaddr,
                                           udp_sport, udp_dport, payload, packet_count, verbose):
    # build inner original header
    inner_eth_header, inner_eth_header_pack = build_eth_header(inner_src_macaddr, inner_dst_macaddr, ETH_TYPE)
    inner_ip_header, inner_ip_header_pack = build_ipv4_header(len(payload)+IP4HEADER.header_size+ICMPHEADER.header_size,
                                                              socket.IPPROTO_ICMP,
                                                              inner_src_ipaddr,
                                                              inner_dst_ipaddr,
                                                              False)
    inner_icmp_header, inner_icmp_header_pack = build_icmp_header(ICMP_TYPE,
                                                                  ICMP_CODE,
                                                                  ICMP_ID,
                                                                  packet_count,
                                                                  payload)
    inner_payload = inner_eth_header_pack + inner_ip_header_pack + inner_icmp_header_pack + payload

    # build vxlan header
    vxlan_header, vxlan_header_pack = build_vxlan_header(VXLAN_FLAGS,
                                                         VXLAN_RESERVED,
                                                         VXLAN_VNI,
                                                         VXLAN_RESERVED2)
    # build outer tunnel header
    eth_header, eth_header_pack = build_eth_header(outer_src_macaddr, outer_dst_macaddr, ETH_TYPE)
    ip_header, ip_header_pack = build_ipv4_header(len(inner_payload)+IP4HEADER.header_size+UDPHEADER.header_size+VXLANHEADER.header_size,
                                                  socket.IPPROTO_UDP,
                                                  outer_src_ipaddr,
                                                  outer_dst_ipaddr,
                                                  False)
    udp_header, udp_header_pack = build_udp_header(udp_sport,
                                                   udp_dport,
                                                   ip_header,
                                                   inner_payload+vxlan_header_pack)

    if verbose == "on":
        print_eth_header(eth_header)
        print_ip4_header(ip_header)
        print_udp_header(udp_header)
        print_vxlan_header(vxlan_header)
        print_eth_header(inner_eth_header)
        print_ip4_header(inner_ip_header)
        print_icmp_header(inner_icmp_header)
        print "=" * 80

    return eth_header_pack + ip_header_pack + udp_header_pack + vxlan_header_pack + inner_payload

def int_from_bytes(s):
    return sum(ord(c) << (i * 8) for i, c in enumerate(s[::-1]))

def compute_internet_checksum(data):
    checksum = 0
    n = len(data) % 2

    pad = bytearray('', encoding='UTF-8')
    if n == 1:
        pad = bytearray(b'\x00')

    for i in range(0, len(data)-1, 2):
        checksum += (ord(data[i]) << 8) + (ord(data[i+1]))
    if n == 1:
        checksum += (ord(data[len(data)-1]) << 8) + (pad[0])
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = ~checksum & 0xFFFF
    return checksum

def print_eth_header(eth_header):
    print "Eth Dst MAC: %s, Src MAC: %s, Ethertype: %s" % (
            eth_header.get_dst_macaddr(), eth_header.get_src_macaddr(), eth_header.get_ethertype())

def print_ip4_header(ip_header):
    print "IP Version: %s, IP Header Length: %s, TTL: %s, Protocol: %s, Src IP: %s, Dst IP: %s" % (
            ip_header.ip_ver, ip_header.ip_ihl, ip_header.ip_ttl, ip_header.ip_proto, ip_header.get_src_ipaddr(), ip_header.get_dst_ipaddr())

def print_icmp_header(icmp_header):
    print "ICMP ID: %s, Seq: %s, CheckSum: %s" % (
            icmp_header.icmp_id, icmp_header.icmp_seq, icmp_header.icmp_chksum)

def print_udp_header(udp_header):
    print "UDP Src Port: %s, Dst Port: %s, Length: %s, Checksum: %s" % (
            udp_header.udp_sport, udp_header.udp_dport, udp_header.udp_len, udp_header.udp_chksum)

def print_vxlan_header(vxlan_header):
    print "VxLAN VNI: %s, flags: %.2x" % (
            vxlan_header.vni, vxlan_header.flags)

def main():
    parse = argparse.ArgumentParser(description="This is an packet generator tool, you can use it to send vxlan packets.", prog="vxlan_send.py")
    parse.add_argument("-i", "--interface",
            help="Specify the interface to send vxlan packets")
    parse.add_argument("-v", "--verbose",
            help="Get some detail information. By default, this value is set to off", default="off")
    parse.add_argument("--outer-src-ipaddr",
            help="Specify the outer source IP adress", default=None)
    parse.add_argument("--outer-dst-ipaddr",
            help="Specify the outer destination IP adress", default=None)
    parse.add_argument("--outer-src-macaddr",
            help="Specify the outer source MAC address", default=None)
    parse.add_argument("--outer-dst-macaddr",
            help="Specify the outer destination MAC address", default=None)
    parse.add_argument("--inner-src-ipaddr",
            help="Specify the inner source IP adress", default=None)
    parse.add_argument("--inner-dst-ipaddr",
            help="Specify the inner destination IP adress", default=None)
    parse.add_argument("--inner-src-macaddr",
            help="Specify the inner source MAC address", default=None)
    parse.add_argument("--inner-dst-macaddr",
            help="Specify the inner destination MAC address", default=None)
    parse.add_argument("--udp-sport",
            help="Specify the UDP source port", default=None)
    parse.add_argument("--udp-dport",
            help="Specify the UDP destination port. By default, it should be 4789", default=4789)
    args = parse.parse_args()

    send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(int(ETH_TYPE, 16)))
    packet_count = 0

    while True:
        payload = struct.pack("d", time.time())
        send_packet = build_vxlan_packet(args.outer_src_macaddr,
                                         args.outer_dst_macaddr,
                                         args.outer_src_ipaddr,
                                         args.outer_dst_ipaddr,
                                         args.inner_src_macaddr,
                                         args.inner_dst_macaddr,
                                         args.inner_src_ipaddr,
                                         args.inner_dst_ipaddr,
                                         args.udp_sport,
                                         args.udp_dport,
                                         payload,
                                         packet_count,
                                         args.verbose)

        send_socket.bind((args.interface, 0))
        send_socket.send(send_packet)

        packet_count += 1
        time.sleep(1)


if __name__ == "__main__":
    main()
