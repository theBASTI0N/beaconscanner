"""Classes responsible for nRF Receiving."""
import threading
from uptime import uptime
import serial
from beacondecoder import decode
from binascii import hexlify



class BeaconReceiver(object):
    def __init__(self, callback, bt_device_id='/dev/ttyS0', baudrate=115200, timeoutValue=1):
        """Initialize receiver."""
        self._rec = Receiver(callback, bt_device_id, baudrate, timeoutValue)
    
    def start(self):
        """Start beacon receiving."""
        self._mon.start()

    def stop(self):
        """Stop beacon receiving."""
        self._mon.terminate()

class Receiver(threading.Thread):
    """Continously scan for BLE advertisements."""

    def __init__(self, callback, bt_device_id, baudrate, timeoutValue):

        threading.Thread.__init__(self)
        self.keep_going = True
        self.callback = callback
        # Bt device, serial port
        self.bt_device_id = bt_device_id
        # keep track of RSSI values
        self.rssiHistory = {}
        # RSSI history tracker
        self.seen = {}
        #Time beacon was lasst seen
        self.lastSeen = {}
        # once seen more then 10 times
        self.sten = {}

    def run(self):
        """Continously receive BLE advertisements."""
        self.socket = self.serial.Serial(bt_device_id, baudrate, timeout=timeoutValue)

        while self.keep_going:
            pkt = self.socket.readline()
            pkt = str(pkt)
            pkt = pkt[2:-4]
            pkt = pkt.splt(",")
            if len(pkt[3]) > 6:
                # BLE advertisement is more than 020106
                self.process_packet(pkt)
        self.socket.close()
    
    def process_packet(self, pkt):
        """Parse the packet and call callback if one of the filters matches."""

        # check if this could be a valid packet before parsing
        # this reduces the CPU load significantly
        if  ( \
            ('4c000215' in pkt[3]) or \
            ('9904' in pkt[3]) or \
            ('aafe' in pkt[3])):
            bt_addr = pkt[2]
            bt_addr = bt_addr.upper()
            rssi = int(pkt[0])
            chanel = int(pkt[1])
            # strip bluetooth address and parse packet
            packet = pkt[2].upper()
            dec = decode(packet)
            smoothRSSI = self.rHistory(bt_addr, rssi)
            self.callback(bt_addr, rssi, packet, dec, smoothRSSI, channel)
            return

    def rHistory(self, mac, rssi):
        if self.lastSeen.get(mac) == None:
            self.lastSeen[mac] = uptime()
        else:
            timeSince= (uptime() - self.lastSeen[mac]) / 60
            if timeSince >= 2:
                del self.rssiHistory[mac]
                self.lastSeen[mac] = uptime()
            else:
                self.lastSeen[mac] = uptime()
        if self.rssiHistory.get(mac) == None:
            self.seen[mac] = 0
            self.sten[mac] = 0
            self.rssiHistory[mac] = [0] * 10
            self.rssiHistory[mac][0] = rssi
        else:
            if self.sten[mac] == 0:
                self.sten[mac] = 1
            cnt = self.seen[mac] + 1
            if cnt == 10:
                cnt = 0
                self.sten[mac] = 2
            self.rssiHistory[mac][cnt] = rssi
            self.seen[mac] = cnt
        if self.sten[mac] == 0:
            r = rssi
        elif self.sten[mac] == 1:
            r = round(sum(self.rssiHistory[mac])/(cnt + 1))
        else:
            r = round(sum(self.rssiHistory[mac])/10)
        return r
    
    def terminate(self):
        """Signal runner to stop and join thread."""
        self.keep_going = False
        self.join()

s = serial.Serial('/dev/ttyS0', 115200, timeout=1)

while True:
    data = str(s.readline())
    data = data[2:-4]
    data = data.splt(",")
    if len(data[3]) > 6:
        decoded = decode(data[3]
        print(decoded)
