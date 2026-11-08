import io
import ipaddress
import math
import socket
import struct
from datetime import datetime, timezone

import dpkt


MAX_PACKETS = 100_000
SUPPORTED_LINK_TYPES = {1, 101, 228, 229}


class CaptureError(ValueError):
    pass


def _validate_pcap(data):
    magics = {
        b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
        b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>',
    }
    endian = magics.get(data[:4])
    if not endian or len(data) < 24:
        raise CaptureError('Invalid or truncated PCAP header.')
    offset = 24
    while offset < len(data):
        if len(data) - offset < 16:
            raise CaptureError('Truncated PCAP packet header.')
        captured, original = struct.unpack_from(endian + 'II', data, offset + 8)
        offset += 16
        if captured > original or captured > len(data) - offset:
            raise CaptureError('Invalid or truncated PCAP packet.')
        offset += captured


def _validate_pcapng(data):
    if len(data) < 28 or data[:4] != b'\x0a\x0d\x0d\x0a':
        raise CaptureError('Invalid or truncated PCAPNG header.')
    endian = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}.get(data[8:12])
    if not endian:
        raise CaptureError('Invalid PCAPNG byte order.')
    offset = 0
    interfaces = 0
    while offset < len(data):
        if len(data) - offset < 12:
            raise CaptureError('Truncated PCAPNG block.')
        block_type, length = struct.unpack_from(endian + 'II', data, offset)
        if length < 12 or length % 4 or length > len(data) - offset:
            raise CaptureError('Invalid or truncated PCAPNG block.')
        if struct.unpack_from(endian + 'I', data, offset + length - 4)[0] != length:
            raise CaptureError('Invalid PCAPNG block length.')
        if block_type == 0x0A0D0D0A and (offset != 0 or length < 28):
            raise CaptureError('Multiple PCAPNG sections are not supported.')
        if block_type == 1:
            interfaces += 1
            if length < 20 or interfaces > 1:
                raise CaptureError('PCAPNG files must contain exactly one interface.')
        if block_type == 3:
            raise CaptureError('PCAPNG simple packet blocks are not supported.')
        if block_type in (2, 6):
            if length < 32 or interfaces != 1:
                raise CaptureError('Invalid PCAPNG packet block.')
            interface = struct.unpack_from(endian + ('H' if block_type == 2 else 'I'), data, offset + 8)[0]
            captured, original = struct.unpack_from(endian + 'II', data, offset + 20)
            if interface != 0 or captured > original or (captured + 3) // 4 * 4 > length - 32:
                raise CaptureError('Invalid PCAPNG packet data.')
        offset += length
    if interfaces != 1:
        raise CaptureError('PCAPNG files must contain exactly one interface.')


def _packet_metadata(timestamp, raw, link_type, number):
    if not math.isfinite(float(timestamp)):
        raise CaptureError('Capture contains an invalid timestamp.')
    try:
        time = datetime.fromtimestamp(float(timestamp), timezone.utc).isoformat(timespec='microseconds')
    except (ValueError, OverflowError, OSError):
        raise CaptureError('Capture contains an invalid timestamp.') from None
    result = {'number': number, 'timestamp': time, 'epoch': float(timestamp), 'source': '',
              'destination': '', 'source_port': None, 'destination_port': None,
              'protocol': 'Other', 'length': len(raw)}
    try:
        if link_type == 1:
            frame = dpkt.ethernet.Ethernet(raw)
            network = frame.data
            if frame.type == dpkt.ethernet.ETH_TYPE_ARP:
                result['protocol'] = 'ARP'
        else:
            version = raw[0] >> 4
            network = dpkt.ip.IP(raw) if version == 4 else dpkt.ip6.IP6(raw) if version == 6 else None
        if isinstance(network, (dpkt.ip.IP, dpkt.ip6.IP6)):
            result['source'] = socket.inet_ntop(socket.AF_INET if len(network.src) == 4 else socket.AF_INET6, network.src)
            result['destination'] = socket.inet_ntop(socket.AF_INET if len(network.dst) == 4 else socket.AF_INET6, network.dst)
            protocol = network.p if isinstance(network, dpkt.ip.IP) else network.nxt
            result['protocol'] = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 58: 'ICMPv6'}.get(protocol, 'IPv4' if len(network.src) == 4 else 'IPv6')
            transport = network.data
            if isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                result['source_port'], result['destination_port'] = transport.sport, transport.dport
    except (dpkt.Error, ValueError, IndexError, struct.error):
        pass
    return result


def parse_capture(filename, data):
    extension = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
    if extension not in ('pcap', 'pcapng'):
        raise CaptureError('Choose a .pcap or .pcapng capture file.')
    try:
        if extension == 'pcap':
            _validate_pcap(data)
            reader = dpkt.pcap.Reader(io.BytesIO(data))
        else:
            _validate_pcapng(data)
            reader = dpkt.pcapng.Reader(io.BytesIO(data))
        link_type = reader.datalink()
        if link_type not in SUPPORTED_LINK_TYPES:
            raise CaptureError('Unsupported capture link type. Use Ethernet or raw IP.')
        packets = []
        for timestamp, raw in reader:
            if len(packets) >= MAX_PACKETS:
                raise CaptureError(f'Capture exceeds the {MAX_PACKETS:,}-packet limit.')
            packets.append(_packet_metadata(timestamp, raw, link_type, len(packets) + 1))
        return packets
    except CaptureError:
        raise
    except (dpkt.Error, ValueError, IndexError, struct.error, OverflowError):
        raise CaptureError('The capture is malformed or unsupported.') from None


def filter_packets(packets, filters):
    def matches(packet):
        for field in ('source', 'destination'):
            if filters.get(field) and filters[field].lower() not in packet[field].lower():
                return False
        if filters.get('ip') and not any(filters['ip'].lower() in packet[field].lower() for field in ('source', 'destination')):
            return False
        if filters.get('protocol') and packet['protocol'].lower() != filters['protocol'].lower():
            return False
        for field in ('source_port', 'destination_port'):
            if filters.get(field) and str(packet[field]) != filters[field]:
                return False
        if filters.get('start') not in ('', None) and packet['epoch'] < filters['start']:
            return False
        if filters.get('end') not in ('', None) and packet['epoch'] > filters['end']:
            return False
        if filters.get('search') and not any(filters['search'].lower() in str(packet[field]).lower() for field in ('source', 'destination', 'protocol', 'source_port', 'destination_port')):
            return False
        return True
    return [packet for packet in packets if matches(packet)]


def ip_sort_key(value):
    try:
        address = ipaddress.ip_address(value)
        return (address.version, int(address))
    except ValueError:
        return (0, 0)