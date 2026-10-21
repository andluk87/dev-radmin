#!/usr/bin/env python3
"""Extract selected IPv4 TCP/17301 frames from Windows NDIS ETL, entirely offline.

Only single-event Ethernet packets (NDIS event 1001) are supported. Other event
types/media and fragmented ETW packets are counted, never silently concatenated.
Optional PCAP and the original ETL contain private packet contents: keep them out of Git.
"""
import argparse
import json
import socket
import struct
from collections import Counter, defaultdict
from pathlib import Path
from uuid import UUID

import dpkt
from dissect.etl import ETL

NDIS = UUID('2ed6006e-4729-4609-b423-3ee7bcd678ef')
MAX_FRAME = 1 << 20
MAX_STREAM = 8 << 20


def split_frames(data):
    frames = []
    at = 0
    while at + 4 <= len(data):
        length = int.from_bytes(data[at:at+4], 'big')
        if length > MAX_FRAME:
            return frames, len(data)-at, 'advertised_length_exceeds_limit'
        if at + 4 + length > len(data):
            return frames, len(data)-at, 'incomplete_frame'
        frames.append(length)
        at += 4 + length
    return frames, len(data)-at, 'partial_header' if at != len(data) else None


def reassemble(segments, base):
    """Handle out-of-order/duplicate/overlapping TCP data; never join across gaps."""
    output = bytearray()
    conflicts = 0
    gap = False
    ordered = sorted((((seq-base) & 0xffffffff), data) for seq, data in segments)
    for offset, data in ordered:
        if offset > len(output):
            gap = True
            break
        overlap = min(len(data), len(output)-offset)
        if output[offset:offset+overlap] != data[:overlap]:
            conflicts += 1
        if offset + len(data) > MAX_STREAM:
            raise ValueError('stream exceeds safety limit')
        output.extend(data[overlap:])
    return bytes(output), gap, conflicts


def extract(path, server, port, pcap_path=None):
    counters = Counter()
    ethertypes = Counter()
    packets = []
    with path.open('rb') as source:
        trace = ETL(source)
        trace_info = {'start_utc': trace.start.isoformat(), 'end_utc': trace.end.isoformat(),
                      'buffers_written': trace.logfile_header.buffers_written}
        for record in trace:
            counters['events'] += 1
            header = record.header
            if type(header).__name__ != 'EventHeader':
                continue
            # Use the raw little-endian GUID: dissect.etl 3.14 EventHeader.provider_id
            # currently interprets these bytes in the opposite order.
            if UUID(bytes_le=bytes(header.header.ProviderId)) != NDIS:
                continue
            counters['ndis_events'] += 1
            if header.header.Id != 1001:
                counters['unsupported_ndis_event'] += 1
                continue
            keywords = header.header.Keywords
            if keywords & 0xc0000000 != 0xc0000000 or keywords & 0x10000:
                counters['unsupported_fragment_or_media'] += 1
                continue
            payload = bytes(header.payload)
            if len(payload) < 12:
                counters['short_ndis_header'] += 1
                continue
            length = struct.unpack_from('<I', payload, 8)[0]
            if length > len(payload)-12:
                counters['truncated_ndis_event'] += 1
                continue
            raw = payload[12:12+length]
            try:
                ethernet = dpkt.ethernet.Ethernet(raw)
                ethertypes[f'0x{ethernet.type:04x}'] += 1
                ip = ethernet.data
                if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data
                src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
                if not ((src == server and tcp.sport == port) or (dst == server and tcp.dport == port)):
                    continue
                packets.append((header.timestamp.timestamp(), raw, src, tcp.sport, dst, tcp.dport,
                                tcp.seq, tcp.ack, tcp.flags, bytes(tcp.data)))
            except (dpkt.UnpackError, ValueError, IndexError):
                counters['unparsed_ethernet_packets'] += 1
    packets.sort(key=lambda item: item[0])
    counters['selected_tcp_observations'] = len(packets)
    if not packets:
        raise ValueError('no matching TCP packets; capture does not validate the control workflow')
    if pcap_path:
        with pcap_path.open('wb') as target:
            writer = dpkt.pcap.Writer(target, snaplen=65535)
            for packet in packets:
                writer.writepkt(packet[1], ts=packet[0])
    sessions = {}
    seen = set()
    for packet in packets:
        timestamp, raw, src, sport, dst, dport, seq, ack, flags, data = packet
        fingerprint = (src, sport, dst, dport, seq, ack, flags, data)
        if fingerprint in seen:
            counters['duplicate_tcp_observations'] += 1
            continue
        seen.add(fingerprint)
        incoming = src == server
        client = (dst, dport) if incoming else (src, sport)
        if client not in sessions:
            sessions[client] = {'client_to_server': {'syn': None, 'segments': []},
                                'server_to_client': {'syn': None, 'segments': []}}
        stream = sessions[client]['server_to_client' if incoming else 'client_to_server']
        if flags & dpkt.tcp.TH_SYN:
            stream['syn'] = (seq+1) & 0xffffffff
        if data:
            stream['segments'].append(((seq+int(bool(flags & dpkt.tcp.TH_SYN))) & 0xffffffff, data))
    summaries = []
    for index, directions in enumerate(sessions.values(), 1):
        summary = {'session': index}
        for name, stream in directions.items():
            segments, syn = stream['segments'], stream['syn']
            body, gap, conflicts = reassemble(segments, syn if syn is not None else segments[0][0]) if segments else (b'', False, 0)
            lengths, unparsed, error = split_frames(body)
            summary[name] = {'syn_seen': syn is not None, 'contiguous_payload_bytes': len(body),
                             'gap': gap, 'conflicting_overlaps': conflicts, 'frame_body_lengths': lengths,
                             'unparsed_bytes': unparsed, 'framing_error': error}
            if syn is not None and body[:8] == bytes.fromhex('0000000403000000'):
                summary[name]['first_frame_u32_le'] = 3
        summaries.append(summary)
    return {'schema_version': 1, 'trace': trace_info, 'counts': dict(counters),
            'captured_ethertypes': dict(ethertypes), 'sessions': summaries,
            'notes': ['Counts include duplicate observations across capture layers.',
                      'Frame boundaries do not imply decoded or authenticated messages.',
                      'No IP addresses or opaque payloads are included in this JSON report.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('etl', type=Path)
    address = parser.add_mutually_exclusive_group(required=True)
    address.add_argument('--server', help='control-server IPv4 address from the local metadata')
    address.add_argument('--metadata', type=Path, help='capture-metadata.json (schema 1 or 2)')
    parser.add_argument('--port', type=int, default=17301)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--pcap', type=Path, help='optional PRIVATE filtered capture output')
    args = parser.parse_args()
    if args.metadata:
        metadata = json.loads(args.metadata.read_text(encoding='utf-8-sig'))
        filters = metadata.get('Filter', [])
        if isinstance(filters, str):
            filters = [filters]
        candidates = [item[len('IPv4.Address='):] for item in filters
                      if isinstance(item, str) and item.startswith('IPv4.Address=')]
        if len(candidates) != 1:
            parser.error('metadata must specify exactly one IPv4.Address filter')
        args.server = candidates[0]
    socket.inet_pton(socket.AF_INET, args.server)
    if not 1 <= args.port <= 65535:
        parser.error('invalid TCP port')
    report = extract(args.etl, args.server, args.port, args.pcap)
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(f'Analyzed {len(report["sessions"])} TCP sessions; saved {args.output}')


if __name__ == '__main__':
    main()
