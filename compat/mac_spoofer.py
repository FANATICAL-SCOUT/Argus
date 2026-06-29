"""Backward-compat shim — run with: python compat/mac_spoofer.py spoof [vendor]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.core.mac import MAC_PREFIXES, get_interface_name, generate_random_mac, spoof_mac, restore_mac  # noqa: F401


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python compat/mac_spoofer.py spoof [vendor] | restore")
        sys.exit(1)

    command = sys.argv[1].lower()
    interface = get_interface_name()
    if not interface:
        print("[!] No suitable network interface found")
        sys.exit(1)

    if command == "spoof":
        vendor = sys.argv[2] if len(sys.argv) > 2 else None
        success, original = spoof_mac(interface, vendor=vendor)
        if success and original:
            try:
                with open(".mac_original", "w") as f:
                    f.write(f"{interface},{original}")
            except Exception:
                print("[!] Warning: Could not save original MAC address")
    elif command == "restore":
        try:
            with open(".mac_original") as f:
                data = f.read().strip().split(",")
                if len(data) == 2:
                    restore_mac(data[0], data[1])
                else:
                    print("[!] Invalid saved MAC data")
        except FileNotFoundError:
            print("[!] No saved original MAC address found")
        except Exception as e:
            print(f"[!] Error restoring MAC: {e}")
