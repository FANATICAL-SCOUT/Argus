"""
Mock OpenFlow SDN Controller — for demo purposes only.
Listens on ports 6633 and 6653 (standard OpenFlow ports).
When the topology scanner scans your subnet, your machine will be
detected as an SDN controller node.

Run this BEFORE clicking "Discover Network" in the topology page.
Stop it with Ctrl+C when done.
"""
import socket
import threading


def _listen(port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        s.listen(10)
        print(f"[Mock SDN] Listening on port {port}")
        while True:
            conn, addr = s.accept()
            print(f"[Mock SDN] Connection from {addr[0]} on port {port}")
            conn.close()
    except OSError as e:
        print(f"[Mock SDN] Could not bind port {port}: {e}")
    finally:
        s.close()


if __name__ == "__main__":
    print("=" * 50)
    print("  Mock OpenFlow SDN Controller (DEMO)")
    print("  Your machine will appear as an SDN node")
    print("  in the topology scan.")
    print("  Press Ctrl+C to stop.")
    print("=" * 50)

    for port in [6633, 6653]:
        t = threading.Thread(target=_listen, args=(port,), daemon=True)
        t.start()

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[Mock SDN] Stopped.")
