import time
import sys
from pybluez2mqtt import BeaconScanner

def callback(bt_addr, rssi, packet, dec):
    print((bt_addr, rssi, packet, dec))

def main_loop():
    # scan for all Estimote telemetry packets from a specific beacon
    global scanner
    scanner = BeaconScanner(callback)
    scanner.start()

if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        scanner.stop()
        print("\nExiting application\n")
        # exit the application
        sys.exit(0)