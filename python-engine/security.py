"""Core security scanner for local network discovery, port scanning, and anomaly detection."""

import json
import os
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from ipaddress import IPv4Network

import psutil


def get_local_subnet():
    """Return the local IPv4 subnet as a string like 10.0.0.0/24."""
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                netmask = addr.netmask
                if netmask:
                    prefix_len = sum(bin(int(x)).count("1") for x in netmask.split("."))
                    network = IPv4Network(f"{addr.address}/{prefix_len}", strict=False)
                    return str(network)
    return None


def ping_host(ip, timeout=1):
    """Return True if host responds to ping, else False."""
    import platform as _platform
    try:
        if _platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), str(ip)]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), str(ip)]
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except Exception:
        return False


def ping_sweep(subnet, max_workers=50):
    """Ping every host in a subnet and return responsive IPs."""
    network = IPv4Network(subnet, strict=False)
    responsive = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in network.hosts()}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            if future.result():
                responsive.append(str(ip))
    return responsive


def tcp_port_scan(ip, ports, timeout=0.5):
    """Scan a list of TCP ports using connect scan. Return open ports."""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except Exception:
            pass
    return open_ports


def resolve_hostname(ip):
    """Try to resolve a hostname from an IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def get_mac_vendor(mac):
    """Return vendor name from MAC OUI if known."""
    # Simple built-in OUI list; in production, use a proper OUI database.
    oui_map = {
        "Apple": ["00:03:93", "00:05:02", "00:0A:27", "00:0A:95", "00:14:51", "00:17:F2", "00:1C:B3", "00:1D:4F", "00:1E:52", "00:1E:C2", "00:1F:5B", "00:1F:F3", "00:21:E9", "00:22:41", "00:23:12", "00:23:32", "00:23:6C", "00:23:DF", "00:24:36", "00:25:00", "00:25:4B", "00:25:BC", "00:26:08", "00:26:4A", "00:26:B0", "00:26:BB", "00:3E:E1", "00:50:E4", "00:56:CD", "00:61:71", "00:6D:52", "00:88:65", "00:90:96", "00:9A:CA", "00:A0:40", "00:A0:99", "00:B0:52", "00:B3:62", "00:B5:6D", "00:C0:CE", "00:C3:F4", "00:C6:10", "00:CB:3E", "00:CD:FE", "00:D0:4B", "00:DB:70", "00:E0:4C", "04:0C:CE", "04:1E:64", "04:26:65", "04:2A:E2", "04:48:C6", "04:4B:ED", "04:52:F3", "04:54:53", "04:69:F8", "04:79:70", "04:8D:38", "04:B1:67", "04:CB:88", "04:DB:8A", "04:E5:36", "04:F7:E5", "08:05:66", "08:6D:41", "08:74:02", "08:8C:2C", "08:9E:08", "08:C7:B5", "08:E6:89", "0C:15:C5", "0C:19:F8", "0C:2A:69", "0C:3E:9F", "0C:4D:E9", "0C:51:01", "0C:74:00", "0C:85:25", "0C:96:E6", "10:00:3E", "10:1D:C0", "10:2F:6B", "10:40:0E", "10:44:00", "10:93:E9", "10:9F:A9", "10:A5:D0", "10:DD:B1", "10:E6:AE", "14:10:9F", "14:20:5E", "14:3C:C3", "14:49:E0", "14:59:C0", "14:5A:05", "14:7D:DA", "14:99:34", "14:9F:3C", "14:A7:2B", "14:BD:61", "14:C1:4E", "18:8E:EF", "18:9E:29", "18:AF:61", "18:B4:30", "18:E7:F4", "18:F1:D8", "1C:1A:C0", "1C:1D:86", "1C:5F:2B", "1C:91:80", "1C:9E:46", "1C:AB:34", "1C:AF:05", "1C:B0:94", "1C:E5:C3", "20:28:3E", "20:3D:66", "20:64:32", "20:76:8E", "20:AB:37", "20:C9:D8", "20:EE:28", "24:1E:EB", "24:4B:03", "24:5E:48", "24:AB:81", "24:E3:14", "28:0A:EE", "28:37:37", "28:6A:BA", "28:AE:00", "28:BE:03", "28:CF:DA", "28:E1:4C", "28:E7:CF", "28:F0:76", "2C:0E:3D", "2C:1F:23", "2C:20:0B", "2C:33:11", "2C:41:38", "2C:82:1B", "2C:8A:72", "2C:BE:08", "2C:CF:58", "2C:D0:F9", "2C:F0:A2", "30:10:E4", "30:35:AD", "30:42:40", "30:63:6A", "30:90:AB", "30:9C:23", "30:B5:C2", "30:D6:C9", "30:F7:C5", "34:08:BC", "34:12:F9", "34:15:13", "34:36:3B", "34:42:62", "34:51:AA", "34:80:64", "34:95:DB", "34:AB:95", "34:C0:59", "34:E8:94", "38:18:51", "38:35:FB", "38:37:8B", "38:48:4C", "38:71:DE", "38:8B:59", "38:C0:96", "38:F9:D3", "3C:07:54", "3C:2E:F9", "3C:5A:37", "3C:61:20", "3C:7D:0A", "3C:AB:8E", "3C:CD:5D", "3C:D0:F8", "3C:E0:72", "3C:F6:92", "40:30:04", "40:4D:8F", "40:82:9A", "40:9C:28", "40:A6:48", "40:B3:95", "40:C2:BA", "40:CB:9B", "40:D3:2D", "40:E7:30", "40:F5:20", "44:00:10", "44:2A:60", "44:44:4B", "44:66:FC", "44:89:DC", "44:94:5C", "44:9E:BE", "44:B2:95", "44:C2:06", "44:D2:CA", "44:D7:91", "48:4B:AA", "48:60:5F", "48:6D:42", "48:74:6E", "48:8D:36", "48:BF:6B", "48:C7:96", "48:D7:05", "48:E9:F1", "4C:20:B8", "4C:32:75", "4C:56:9D", "4C:7C:5F", "4C:8B:EF", "4C:BC:A5", "4C:E1:06", "50:32:37", "50:76:AF", "50:82:D5", "50:9F:27", "50:A6:7E", "50:BC:96", "50:DE:06", "50:ED:3C", "54:1B:AD", "54:26:96", "54:33:CB", "54:4A:16", "54:72:4F", "54:99:63", "54:9F:13", "54:E4:3A", "58:1F:28", "58:40:4E", "58:7F:57", "58:93:96", "58:A8:39", "58:B0:35", "58:D9:C3", "58:E2:8F", "5C:09:47", "5C:52:30", "5C:8D:4E", "5C:95:42", "5C:96:9D", "5C:A8:21", "5C:AD:AD", "5C:CB:99", "5C:E5:0B", "60:03:08", "60:30:D4", "60:33:5B", "60:69:44", "60:8B:0E", "60:92:66", "60:A3:7D", "60:AF:6D", "60:C5:47", "60:D7:E3", "60:E3:AC", "60:F4:45", "64:10:8D", "64:20:0C", "64:59:F8", "64:6C:80", "64:70:02", "64:9A:BE", "64:A2:F9", "64:B0:A6", "64:B5:3F", "64:BC:0C", "64:C7:DD", "64:D4:DA", "64:E7:D8", "68:09:27", "68:54:FD", "68:96:7B", "68:9C:70", "68:AE:20", "68:D9:3C", "68:FB:97", "6C:19:8F", "6C:3E:6D", "6C:40:08", "6C:4D:73", "6C:72:20", "6C:96:CF", "6C:AB:31", "6C:AD:EF", "6C:C2:6B", "70:14:A6", "70:35:60", "70:3E:AC", "70:48:0F", "70:56:81", "70:69:F5", "70:70:0D", "70:79:90", "70:A2:B3", "70:AF:25", "74:19:F8", "74:1B:B2", "74:2D:0E", "74:59:09", "74:81:14", "74:88:2A", "74:9E:AF", "74:E1:55", "74:E7:C6", "78:31:C1", "78:3A:84", "78:4F:43", "78:6C:1C", "78:7E:61", "78:93:5C", "78:9F:E8", "78:AB:BB", "78:CA:04", "78:F8:82", "7C:04:D0", "7C:11:CB", "7C:2A:DB", "7C:3E:9D", "7C:5A:1F", "7C:6D:62", "7C:8B:CA", "7C:9A:54", "7C:A1:AE", "7C:C3:A1", "7C:C5:37", "7C:EC:64", "80:00:6E", "80:1F:12", "80:36:6E", "80:49:71", "80:65:6D", "80:82:23", "80:97:33", "80:9F:9B", "80:A1:AB", "80:B0:55", "80:BE:05", "80:E4:15", "80:EA:96", "84:38:35", "84:40:66", "84:63:D6", "84:85:06", "84:89:AD", "84:8D:0E", "84:B1:53", "84:BA:20", "84:BE:52", "84:CF:BF", "84:D3:1D", "84:E8:92", "88:19:37", "88:3F:D8", "88:51:FB", "88:63:DF", "88:66:A5", "88:6B:6E", "88:75:8E", "88:7A:06", "88:A9:B7", "88:AD:43", "88:B1:44", "88:CB:87", "88:E0:87", "88:E8:7F", "88:F0:31", "8C:28:98", "8C:2D:AA", "8C:58:77", "8C:59:3A", "8C:5E:5C", "8C:7A:86", "8C:85:80", "8C:8E:76", "8C:9C:DC", "8C:A8:7F", "8C:CB:EF", "90:18:7C", "90:2C:45", "90:60:F1", "90:69:C2", "90:72:40", "90:84:0D", "90:91:92", "90:9A:4A", "90:B2:1F", "90:B9:31", "90:BC:44", "90:BF:BE", "90:D3:95", "90:E1:7A", "94:04:9C", "94:0C:6D", "94:27:90", "94:44:44", "94:64:24", "94:94:26", "94:99:90", "94:A1:A2", "94:B5:DB", "94:BA:3F", "94:E1:AC", "98:00:C6", "98:03:CF", "98:09:CF", "98:46:0A", "98:5A:EB", "98:9C:57", "98:9E:63", "98:A9:1E", "98:AE:71", "98:B8:BC", "98:CA:53", "98:D6:BB", "98:F1:70", "9C:04:EB", "9C:20:67", "9C:35:83", "9C:4F:DA", "9C:99:A5", "9C:B2:20", "9C:F3:87", "A0:18:28", "A0:3B:E3", "A0:4E:A7", "A0:60:32", "A0:65:6C", "A0:88:ED", "A0:98:05", "A0:9F:10", "A0:A3:3B", "A0:B4:48", "A0:CE:C8", "A0:D7:10", "A0:ED:CD", "A4:18:C6", "A4:1F:72", "A4:34:F1", "A4:5E:60", "A4:83:E7", "A4:91:62", "A4:B1:E2", "A4:C3:61", "A4:CF:99", "A4:D8:78", "A4:E9:90", "A4:F1:E8", "A8:34:6A", "A8:5B:78", "A8:66:7F", "A8:6D:AA", "A8:96:8A", "A8:9F:BA", "A8:BB:CF", "A8:BE:27", "A8:C7:F3", "A8:D8:8B", "A8:F2:10", "AC:05:19", "AC:10:2E", "AC:1F:74", "AC:29:3A", "AC:3C:0B", "AC:44:F2", "AC:61:EA", "AC:7A:56", "AC:87:A3", "AC:8C:A6", "AC:BC:32", "AC:CF:5C", "AC:D5:C3", "AC:DE:48", "B0:34:95", "B0:48:1A", "B0:65:BD", "B0:6A:41", "B0:8B:CF", "B0:98:2B", "B0:9F:4A", "B0:AC:92", "B0:B1:11", "B0:BE:76", "B0:C4:10", "B0:CA:EB", "B0:D2:F5", "B0:E8:92", "B0:EC:71", "B4:18:D1", "B4:2C:72", "B4:31:B8", "B4:5A:65", "B4:5F:98", "B4:6D:BC", "B4:86:8B", "B4:8B:19", "B4:9C:DF", "B4:A5:EF", "B4:B5:83", "B4:C4:FE", "B4:F0:E3", "B4:F6:17", "B8:09:8A", "B8:17:C2", "B8:2D:FC", "B8:31:B5", "B8:41:5F", "B8:44:61", "B8:53:AC", "B8:78:2E", "B8:81:98", "B8:88:E3", "B8:8D:12", "B8:9A:2D", "B8:9E:EE", "B8:BA:68", "B8:BC:1B", "B8:C6:83", "B8:D7:AF", "B8:E8:56", "B8:EE:0E", "B8:F0:78", "B8:F6:B1", "B8:FF:61", "BC:02:13", "BC:0F:2C", "BC:14:EF", "BC:2C:55", "BC:4C:C4", "BC:52:B7", "BC:54:51", "BC:66:41", "BC:6C:16", "BC:92:6B", "BC:A4:CD", "BC:BA:56", "BC:D0:0A", "BC:DE:1C", "BC:E1:43", "BC:F6:85", "C0:49:EF", "C0:63:94", "C0:84:7A", "C0:9F:05", "C0:A5:DD", "C0:CC:F8", "C0:D0:4D", "C0:E4:22", "C0:F2:FB", "C4:20:32", "C4:34:88", "C4:42:02", "C4:5A:3F", "C4:64:E3", "C4:83:E4", "C4:8B:55", "C4:98:80", "C4:9F:4C", "C4:B3:01", "C4:DC:E5", "C8:2A:14", "C8:2B:CC", "C8:38:70", "C8:3C:85", "C8:47:4D", "C8:4B:1C", "C8:63:F7", "C8:69:CD", "C8:69:F5", "C8:6F:1D", "C8:85:50", "C8:8B:E8", "C8:8D:83", "C8:91:09", "C8:94:02", "C8:9C:DC", "C8:A8:7F", "C8:CB:EF", "CC:08:8D", "CC:20:E8", "CC:25:EF", "CC:29:F5", "CC:40:08", "CC:44:63", "CC:66:0A", "CC:78:5F", "CC:96:A0", "CC:9F:7A", "CC:AF:78", "CC:CC:CC", "CC:D2:81", "D0:03:DF", "D0:22:BE", "D0:33:34", "D0:4F:58", "D0:67:E5", "D0:7E:35", "D0:81:7A", "D0:87:45", "D0:97:6F", "D0:A0:12", "D0:C5:F3", "D0:E0:FB", "D4:33:3D", "D4:4F:49", "D4:61:DA", "D4:63:C6", "D4:8F:AA", "D4:90:9C", "D4:9A:9F", "D4:A0:25", "D4:A3:3D", "D4:AF:F1", "D4:B1:0A", "D4:E6:B7", "D4:F5:27", "D4:FC:13", "D8:00:4D", "D8:08:31", "D8:30:62", "D8:3F:8C", "D8:5E:CE", "D8:60:F5", "D8:61:62", "D8:96:95", "D8:9E:3F", "D8:A2:5E", "D8:A3:97", "D8:B1:7E", "D8:BB:2C", "D8:CF:9C", "D8:D1:CB", "D8:DB:2E", "D8:F0:F5", "D8:F1:CB", "DC:00:6F", "DC:08:0F", "DC:2B:2A", "DC:2B:61", "DC:33:0F", "DC:56:E7", "DC:86:D8", "DC:9B:48", "DC:9B:9C", "DC:A4:CA", "DC:AE:1B", "DC:EE:06", "E0:01:7B", "E0:02:1A", "E0:04:FB", "E0:05:C5", "E0:0A:E2", "E0:5F:45", "E0:66:78", "E0:98:DE", "E0:9D:31", "E0:A8:ED", "E0:B9:BA", "E0:C6:37", "E0:C9:7A", "E0:D5:5E", "E0:F5:C6", "E0:F8:48", "E0:F8:49", "E0:F9:BE", "E4:02:9B", "E4:08:EE", "E4:0E:EE", "E4:11:5B", "E4:2C:D6", "E4:40:E2", "E4:5D:52", "E4:98:39", "E4:9A:54", "E4:9E:12", "E4:B2:19", "E4:C6:3A", "E4:E7:49", "E4:F8:9C", "E8:04:0F", "E8:06:88", "E8:07:BF", "E8:16:2B", "E8:21:5D", "E8:2A:EA", "E8:47:3A", "E8:4C:56", "E8:50:9A", "E8:5A:5B", "E8:5D:6D", "E8:6B:72", "E8:80:2E", "E8:8F:6F", "E8:92:69", "E8:96:06", "E8:99:C4", "E8:B4:56", "E8:BA:8C", "E8:C1:D7", "E8:CB:A8", "E8:D0:FC", "E8:D8:8B", "E8:DD:2C", "EC:10:7B", "EC:26:CA", "EC:2C:3D", "EC:35:86", "EC:36:30", "EC:3E:F7", "EC:5B:73", "EC:85:2F", "EC:8F:DE", "EC:AA:25", "EC:D2:0F", "F0:18:98", "F0:24:75", "F0:5C:D3", "F0:5E:59", "F0:6E:0A", "F0:72:8C", "F0:84:A7", "F0:99:BF", "F0:9E:4A", "F0:9E:AA", "F0:A9:02", "F0:B4:79", "F0:C1:57", "F0:C4:79", "F0:C7:7F", "F0:CB:84", "F0:D1:A9", "F0:DB:E2", "F0:DC:1D", "F0:F6:0C", "F4:31:6C", "F4:37:2B", "F4:4D:30", "F4:55:14", "F4:5C:89", "F4:5E:AB", "F4:75:EF", "F4:7A:05", "F4:7B:5C", "F4:8C:50", "F4:8E:92", "F4:93:9F", "F4:9B:9C", "F4:A4:02", "F4:BF:80", "F4:D3:16", "F4:E3:FA", "F4:F1:5A", "F4:F5:A5", "F4:F9:51", "F8:01:13", "F8:1E:DF", "F8:27:93", "F8:2F:A8", "F8:4D:89", "F8:4E:75", "F8:54:F3", "F8:69:F5", "F8:6F:84", "F8:7B:E6", "F8:84:F2", "F8:8C:85", "F8:95:6A", "F8:9B:FF", "F8:A9:D0", "F8:AC:65", "F8:AD:CB", "F8:CB:5D", "F8:CF:C5", "F8:D0:BD", "F8:E0:79", "F8:E6:8A", "FC:18:3C", "FC:25:3F", "FC:2A:54", "FC:33:CD", "FC:4D:8A", "FC:51:7A", "FC:52:8D", "FC:5A:1F", "FC:65:0E", "FC:6D:68", "FC:74:68", "FC:8F:90", "FC:9C:5E", "FC:A1:0A", "FC:A4:17", "FC:B0:9C", "FC:C2:26", "FC:E8:40", "FC:F8:AE"],
        "Samsung": ["00:12:47", "00:13:77", "00:15:99", "00:17:C4", "00:18:AF", "00:1A:8A", "00:1C:43", "00:1D:25", "00:1E:7D", "00:21:19", "00:23:39", "00:24:54", "00:26:37", "00:30:66", "00:37:6D", "04:18:0F", "04:3E:2A", "08:08:EA", "08:08:88", "08:5D:DD", "0C:14:20", "0C:89:42", "10:2F:6B", "10:41:1D", "10:A5:9D", "10:C7:53", "14:32:80", "14:59:C0", "18:46:44", "18:AF:61", "1C:5A:6B", "1C:62:B8", "20:16:32", "20:6E:9C", "24:4B:81", "28:13:10", "2C:44:01", "30:02:5A", "34:14:5F", "38:2D:E8", "38:AA:3C", "3C:5A:B4", "3C:77:E6", "40:2F:86", "44:00:49", "48:44:73", "4C:FC:65", "50:1D:93", "50:64:CB", "50:91:E3", "54:88:0E", "58:CB:52", "5C:49:79", "5C:E8:EB", "60:AF:6D", "64:1C:AE", "68:4F:F4", "6C:AD:94", "70:14:A6", "74:E6:E2", "78:1F:7C", "7C:5C:F8", "80:1F:02", "84:11:9E", "88:3A:F4", "8C:73:6E", "90:B1:1C", "94:27:90", "9C:8B:BA", "A0:40:25", "A4:08:EA", "A4:67:06", "A8:06:7E", "A8:51:5B", "AC:5F:3E", "AC:9E:17", "B0:47:CF", "B0:98:2B", "B0:C4:E1", "B4:07:F9", "B4:52:7D", "B4:86:51", "B8:5A:73", "B8:97:5A", "BC:1A:67", "BC:44:86", "BC:7E:92", "C0:97:27", "C4:42:02", "C4:57:6E", "C4:73:1E", "C4:86:E9", "C8:14:79", "C8:19:F7", "C8:65:48", "CC:07:AB", "CC:3A:61", "CC:73:14", "D0:19:A6", "D0:66:7B", "D0:C0:BF", "D4:6A:91", "D4:87:D8", "D4:9E:05", "D8:63:14", "D8:E0:E1", "DC:89:83", "E0:63:E5", "E4:7C:F9", "E4:B0:71", "E4:FA:ED", "E8:02:9C", "E8:3A:12", "E8:5B:5B", "E8:92:A4", "EC:9B:F3", "F0:25:B7", "F4:42:8F", "F4:7B:5E", "F4:B8:A7", "F8:3F:51", "F8:77:79", "FC:19:99", "FC:35:E6", "FC:42:65", "FC:7F:F1"],
    }
    prefix = mac.upper()[:8]
    for vendor, prefixes in oui_map.items():
        if prefix in prefixes:
            return vendor
    return "Unknown"


class SecurityScanner:
    """Main scanner class: discovery, port scan, baseline, and alerts."""

    def __init__(self, data_dir=None):
        if data_dir is None:
            data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self.baseline_file = os.path.join(self.data_dir, "baseline.json")
        self.scan_file = os.path.join(self.data_dir, "latest_scan.json")
        self.alerts_file = os.path.join(self.data_dir, "alerts.json")

    def load_baseline(self):
        if not os.path.exists(self.baseline_file):
            return None
        with open(self.baseline_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_baseline(self, devices):
        data = {
            "created_at": datetime.utcnow().isoformat() + "Z",
            "devices": devices,
        }
        with open(self.baseline_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return data

    def save_latest_scan(self, devices):
        data = {
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "devices": devices,
        }
        with open(self.scan_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return data

    def add_alert(self, alert_type, message, device=None):
        alerts = self.load_alerts()
        alert = {
            "id": int(time.time() * 1000),
            "type": alert_type,
            "message": message,
            "device": device,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "read": False,
        }
        alerts.insert(0, alert)
        with open(self.alerts_file, "w", encoding="utf-8") as f:
            json.dump(alerts[:500], f, indent=2)
        return alert

    def load_alerts(self):
        if not os.path.exists(self.alerts_file):
            return []
        with open(self.alerts_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def mark_alert_read(self, alert_id):
        alerts = self.load_alerts()
        for alert in alerts:
            if alert["id"] == alert_id:
                alert["read"] = True
                break
        with open(self.alerts_file, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2)
        return alerts

    def scan(self, subnet=None, ports=None, full_scan=False):
        """Run a full or quick scan and return discovered devices."""
        if subnet is None:
            subnet = get_local_subnet()
        if subnet is None:
            raise RuntimeError("Could not determine local subnet")

        common_ports = [22, 23, 53, 80, 139, 443, 445, 515, 631, 3389, 5900, 7000, 8000, 8080, 8443]
        if full_scan:
            common_ports = list(range(1, 1025)) + [3306, 5432, 6379, 8080, 8443, 8888, 9200]

        if ports is None:
            ports = common_ports

        responsive_ips = ping_sweep(subnet)
        devices = []

        def scan_one(ip):
            hostname = resolve_hostname(ip)
            open_ports = tcp_port_scan(ip, ports)
            return {
                "ip": ip,
                "hostname": hostname or ip,
                "vendor": "Unknown",
                "mac": None,
                "open_ports": open_ports,
                "first_seen": datetime.utcnow().isoformat() + "Z",
            }

        with ThreadPoolExecutor(max_workers=30) as executor:
            for device in executor.map(scan_one, responsive_ips):
                devices.append(device)

        self.save_latest_scan(devices)

        # Compare to baseline and generate alerts
        baseline = self.load_baseline()
        if baseline:
            baseline_ips = {d["ip"] for d in baseline.get("devices", [])}
            current_ips = {d["ip"] for d in devices}
            for device in devices:
                if device["ip"] not in baseline_ips:
                    self.add_alert("new_device", f"New device found: {device['hostname']} ({device['ip']})", device)
            for old_ip in baseline_ips - current_ips:
                old = next((d for d in baseline["devices"] if d["ip"] == old_ip), None)
                self.add_alert("device_removed", f"Device no longer seen: {old.get('hostname', old_ip)}", old)
        else:
            self.add_alert("info", "First scan completed. Save this as your baseline to detect new devices.")

        return devices
