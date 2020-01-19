import time
import sys
from beaconscanner import BeaconReceiver

def callback(bt_addr, rssi, packet, dec, smoothedRSSI, channel):
    if channel != 0:
        print((bt_addr, rssi, smoothedRSSI, packet, dec, channel))
    else:
        print((bt_addr, rssi, smoothedRSSI, packet, dec))

def main_loop():
    # scan for all Estimote telemetry packets from a specific beacon
    global scanner
    scanner = BeaconReceiver(callback)
    scanner.start()

if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        scanner.stop()
        print("\nExiting application\n")
        # exit the application
        sys.exit(0)