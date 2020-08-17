import time
import sys
from beaconscanner import BeaconScanner

def callback(bt_addr, rssi, packet, dec, smoothedRSSI):
    print((bt_addr, rssi, smoothedRSSI, packet, dec))

def main_loop():
    # scan for all Estimote telemetry packets from a specific beacon
    global scanner
    scanner = BeaconScanner(callback, ruuvi=True, ruuviPlus=False, eddystone=True, ibeacon=True, unknown=False)
    scanner.start()
    while True:
        time.sleep(30)
        scanner._mon.toggle_scan(False)
        time.sleep(10)
        scanner._mon.toggle_scan(True)

if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        scanner.stop()
        print("\nExiting application\n")
        # exit the application
        sys.exit(0)
