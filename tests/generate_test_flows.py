#!/usr/bin/env python3
import argparse
import ipaddress
import socket
import struct
import time


def send(sock: socket.socket, host: str, port: int, data: bytes) -> None:
    sock.sendto(data, (host, port))


def v5_packet(src: str, dst: str, vlan_like_if: int, bytes_count: int, packets: int) -> bytes:
    now = int(time.time())
    header = struct.pack("!HHIIIIBBH", 5, 1, 0, now, 0, 1, 0, 0, 0)
    record = struct.pack(
        "!IIIHHIIIIHHBBBBHHBBH",
        int(ipaddress.IPv4Address(src)),
        int(ipaddress.IPv4Address(dst)),
        0,
        vlan_like_if,
        vlan_like_if,
        packets,
        bytes_count,
        0,
        0,
        12345,
        443,
        0,
        24,
        6,
        0,
        0,
        0,
        24,
        24,
        0,
    )
    return header + record


def v9_template_and_data(src: str, dst: str, vlan: int, bytes_count: int, packets: int) -> tuple[bytes, bytes]:
    now = int(time.time())
    source_id = 100
    template_id = 256
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (58, 2), (1, 4), (2, 4)]
    tpl_body = struct.pack("!HH", template_id, len(fields)) + b"".join(struct.pack("!HH", t, l) for t, l in fields)
    tpl_set = struct.pack("!HH", 0, 4 + len(tpl_body)) + tpl_body
    tpl_header = struct.pack("!HHIIII", 9, 1, 0, now, 1, source_id)
    data_body = struct.pack(
        "!IIHHBHI I".replace(" ", ""),
        int(ipaddress.IPv4Address(src)),
        int(ipaddress.IPv4Address(dst)),
        12345,
        443,
        6,
        vlan,
        bytes_count,
        packets,
    )
    data_set = struct.pack("!HH", template_id, 4 + len(data_body)) + data_body
    data_header = struct.pack("!HHIIII", 9, 1, 0, now, 2, source_id)
    return tpl_header + tpl_set, data_header + data_set


def ipfix_template_and_data(src: str, dst: str, vlan: int, bytes_count: int, packets: int) -> tuple[bytes, bytes]:
    now = int(time.time())
    domain_id = 200
    template_id = 256
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (58, 2), (1, 4), (2, 4)]
    tpl_body = struct.pack("!HH", template_id, len(fields)) + b"".join(struct.pack("!HH", t, l) for t, l in fields)
    tpl_set = struct.pack("!HH", 2, 4 + len(tpl_body)) + tpl_body
    tpl_len = 16 + len(tpl_set)
    tpl_header = struct.pack("!HHIII", 10, tpl_len, now, 1, domain_id)
    data_body = struct.pack(
        "!IIHHBHI I".replace(" ", ""),
        int(ipaddress.IPv4Address(src)),
        int(ipaddress.IPv4Address(dst)),
        12345,
        443,
        6,
        vlan,
        bytes_count,
        packets,
    )
    data_set = struct.pack("!HH", template_id, 4 + len(data_body)) + data_body
    data_len = 16 + len(data_set)
    data_header = struct.pack("!HHIII", 10, data_len, now, 2, domain_id)
    return tpl_header + tpl_set, data_header + data_set


def main() -> None:
    parser = argparse.ArgumentParser(description="Send minimal NetFlow v5/v9/IPFIX test packets to the collector.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2055)
    parser.add_argument("--version", choices=["v5", "v9", "ipfix", "all"], default="all")
    parser.add_argument("--vlan", type=int, default=20)
    parser.add_argument("--bytes", type=int, default=50000)
    parser.add_argument("--packets", type=int, default=500)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if args.version in {"v5", "all"}:
            send(sock, args.host, args.port, v5_packet("10.0.20.1", "10.0.20.254", args.vlan, args.bytes, args.packets))
            print("sent NetFlow v5")
        if args.version in {"v9", "all"}:
            tpl, data = v9_template_and_data("10.0.20.2", "10.0.20.254", args.vlan, args.bytes, args.packets)
            send(sock, args.host, args.port, tpl)
            time.sleep(0.1)
            send(sock, args.host, args.port, data)
            print("sent NetFlow v9 template+data")
        if args.version in {"ipfix", "all"}:
            tpl, data = ipfix_template_and_data("10.0.20.3", "10.0.20.254", args.vlan, args.bytes, args.packets)
            send(sock, args.host, args.port, tpl)
            time.sleep(0.1)
            send(sock, args.host, args.port, data)
            print("sent IPFIX template+data")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
