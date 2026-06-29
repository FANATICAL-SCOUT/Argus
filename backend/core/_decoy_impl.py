"""Internal: DecoyScanner implementation (Scapy logic preserved verbatim from v1).

Do not import this directly — use backend.core.decoy.run_decoy_scan instead.
"""
from __future__ import annotations

import os
import random
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from queue import Queue
from typing import List

try:
    from scapy.all import IP, TCP, conf, get_if_addr, get_if_list, send

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class DecoyScanner:
    def __init__(self, target: str, ports, num_decoys: int = 5, timeout: float = 2.0, threads: int = 100):
        self.target = target
        self.ports = self._parse_ports(ports)
        self.num_decoys = num_decoys
        self.timeout = timeout
        self.threads = min(threads, len(self.ports) or 1)
        self.decoys: List[str] = []
        self.open_ports: List[int] = []
        self.port_queue: Queue = Queue()
        self.print_lock = threading.Lock()
        self.interface = None

        if SCAPY_AVAILABLE:
            conf.verb = 0
            self.interface = self._get_best_interface()

    def _get_best_interface(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.target, 80))
            local_ip = s.getsockname()[0]
            s.close()
            if SCAPY_AVAILABLE:
                for iface in get_if_list():
                    try:
                        if get_if_addr(iface) == local_ip:
                            print(f"[*] Using network interface: {iface} ({local_ip})")
                            return iface
                    except Exception:
                        continue
        except Exception as e:
            print(f"[!] Could not determine best interface: {e}")
        return None

    def _parse_ports(self, ports) -> List[int]:
        if isinstance(ports, list):
            return ports
        result: List[int] = []
        if "," in str(ports):
            for p in str(ports).split(","):
                try:
                    result.append(int(p.strip()))
                except ValueError:
                    pass
        elif "-" in str(ports):
            try:
                start, end = map(int, str(ports).split("-"))
                result = list(range(start, end + 1))
            except ValueError:
                pass
        else:
            try:
                result = [int(ports)]
            except ValueError:
                pass
        return result

    def _generate_decoys(self) -> List[str]:
        decoys: List[str] = []
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.target, 80))
            real_ip = s.getsockname()[0]
            s.close()
            decoys.append(real_ip)
        except Exception:
            real_ip = "127.0.0.1"
            decoys.append(real_ip)

        target_parts = self.target.split(".")
        for _ in range(self.num_decoys):
            try:
                first = int(target_parts[0])
            except Exception:
                first = None

            if first in (10, 192):
                decoy_ip = f"{target_parts[0]}.{target_parts[1]}.{target_parts[2]}.{random.randint(1, 254)}"
            elif first == 172:
                try:
                    second = int(target_parts[1])
                    if 16 <= second <= 31:
                        decoy_ip = f"{target_parts[0]}.{target_parts[1]}.{target_parts[2]}.{random.randint(1, 254)}"
                    else:
                        while True:
                            ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
                            if not (ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)):
                                decoy_ip = ip
                                break
                except Exception:
                    decoy_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
            else:
                while True:
                    ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
                    if not (ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)):
                        decoy_ip = ip
                        break
            decoys.append(decoy_ip)

        random.shuffle(decoys)
        display = [f"ME({ip})" if ip == real_ip else ip for ip in decoys]
        print(f"[*] Using decoys: {', '.join(display)}")
        return decoys

    def _worker(self):
        while not self.port_queue.empty():
            try:
                port = self.port_queue.get(block=False)
            except Exception:
                break

            with self.print_lock:
                if len(self.ports) < 100:
                    print(f"[*] Scanning port {port} with decoys... ", end="", flush=True)

            if SCAPY_AVAILABLE:
                for decoy_ip in self.decoys:
                    try:
                        pkt = IP(src=decoy_ip, dst=self.target) / TCP(dport=port, flags="S")
                        send(pkt, verbose=0)
                    except Exception:
                        pass

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                if s.connect_ex((self.target, port)) == 0:
                    self.open_ports.append(port)
                    with self.print_lock:
                        if len(self.ports) < 100:
                            print("Open!")
                        else:
                            print(f"[+] Port {port} is open")
                    s.close()
                elif len(self.ports) < 100:
                    with self.print_lock:
                        print("Closed")
            except Exception:
                if len(self.ports) < 100:
                    with self.print_lock:
                        print("Error")

            self.port_queue.task_done()

    def scan(self) -> List[int]:
        print(f"[*] Starting multithreaded decoy scan against {self.target}")
        print(f"[*] Scanning {len(self.ports)} ports with {self.num_decoys} decoys using {self.threads} threads")
        if not SCAPY_AVAILABLE:
            print("[!] Scapy library not available. Using basic scan mode.")
            print("[!] Install Scapy for full decoy functionality: pip install scapy")

        self.decoys = self._generate_decoys()
        for port in self.ports:
            self.port_queue.put(port)

        start_time = time.time()
        thread_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            t.start()
            thread_list.append(t)

        total_ports = len(self.ports)
        try:
            while not self.port_queue.empty():
                remaining = self.port_queue.qsize()
                completed = total_ports - remaining
                progress = (completed / total_ports) * 100 if total_ports else 100
                if total_ports > 100:
                    print(f"[*] Progress: {progress:.1f}% ({completed}/{total_ports}) - Open: {len(self.open_ports)}")
                time.sleep(2)
                if sum(1 for t in thread_list if t.is_alive()) == 0 and not self.port_queue.empty():
                    print("[!] All worker threads stopped but scan not complete.")
                    break
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user. Showing partial results.")

        duration = time.time() - start_time
        print(f"\n[+] Scan completed in {duration:.2f} seconds")
        print(f"[+] Found {len(self.open_ports)} open ports on {self.target}")

        if self.open_ports:
            print("\nPORT     STATE   SERVICE")
            print("------------------------")
            for port in sorted(self.open_ports):
                try:
                    service = socket.getservbyport(port) if port < 1024 else "unknown"
                except Exception:
                    service = "unknown"
                print(f"{port:<8} open    {service}")

        # Save to data/records/
        try:
            from backend.config.settings import Settings
            Settings.ensure_dirs()
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out = Settings.RECORDS_DIR / f"decoy_scan_{self.target}_{ts}.txt"
            with open(out, "w") as f:
                f.write(f"# Decoy Scan Results for {self.target}\n")
                f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Ports scanned: {len(self.ports)}\n")
                f.write(f"# Decoys used: {self.num_decoys}\n")
                f.write(f"# Scan duration: {duration:.2f} seconds\n\n")
                if self.open_ports:
                    f.write("PORT     STATE   SERVICE\n")
                    f.write("------------------------\n")
                    for port in sorted(self.open_ports):
                        try:
                            service = socket.getservbyport(port) if port < 1024 else "unknown"
                        except Exception:
                            service = "unknown"
                        f.write(f"{port:<8} open    {service}\n")
            print(f"[*] Results saved to {out}")
        except Exception as e:
            print(f"[!] Could not save results to file: {e}")

        return self.open_ports
