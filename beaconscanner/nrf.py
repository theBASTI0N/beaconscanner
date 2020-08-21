"""Classes responsible for nRF Receiving."""
import threading
from uptime import uptime
import serial
from beacondecoder import decode
from binascii import hexlify
from .const import Ibeacon_String



class BeaconReceiver(object):
    def __init__(self, callback, bt_device_id='/dev/ttyS0', baudrate=115200, timeoutValue=1, rssiThreshold=-999, ruuvi=True, ruuviPlus=False, eddystone=True, ibeacon=True, unknown=True):
        """Initialize receiver."""
        self._rec = Receiver(callback, bt_device_id, baudrate, timeoutValue, rssiThreshold, ruuvi, ruuviPlus, eddystone, ibeacon, unknown)
    
    def start(self):
        """Start beacon receiving."""
        self._rec.start()

    def stop(self):
        """Stop beacon receiving."""
        self._rec.terminate()

class Receiver(threading.Thread):
    """Continously scan for BLE advertisements."""

    def __init__(self, callback, bt_device_id, baudrate, timeoutValue, rssiThreshold, ruuvi, ruuviPlus, eddystone, ibeacon, unknown):

        threading.Thread.__init__(self)
        self.keep_going = True
        self.callback = callback
        self.baudrate = baudrate
        self.timeoutValue = timeoutValue
        # RSSI Threshold, if enabled device with lower power will not be sent
        self.rssiThreshold = rssiThreshold
        # Bt device, serial port
        self.bt_device_id = bt_device_id
        self.ruuvi = ruuvi
        self.ruuviPlus = ruuviPlus
        # list of packet types to monitor
        self.eddystone = eddystone
        self.ibeacon = ibeacon
        self.unknown = unknown
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
        
        self.socket = serial.Serial(self.bt_device_id, self.baudrate, timeout=self.timeoutValue)

        while self.keep_going:
            try:
                pkt = self.socket.readline()
                pkt = str(pkt)
                pkt = pkt.upper()
                pkt = pkt[2:-4]
                pkt = pkt.split(",")
                if len(pkt[3]) > 6:
                    # BLE advertisement is more than 020106
                    self.process_packet(pkt)
            except:
                #used if readline was blank
                pass
        self.socket.close()
    
    def process_packet(self, pkt):
        """Parse the packet and call callback if one of the filters matches."""

        # check if this could be a valid packet before parsing
        # this reduces the CPU load significantly
        if  ( \
            (self.ibeacon and Ibeacon_String in pkt[1]) or \
            (self.ruuvi and '9904' in pkt[1]) or \
            (self.eddystone and 'AAFE' in pkt[1])):
            bt_addr = pkt[0]
            rssi = int(pkt[2])

            # strip bluetooth address and parse packet
            packet = pkt[1]
            try:
                dec = decode(packet, self.ruuviPlus)
                if(dec['dataFormat'] != 0): #Beacon most likely ibeacon or eddstone URL/UID. FIX needed
                    smoothRSSI = self.rHistory(bt_addr, rssi)
                    if smoothRSSI >= self.rssiThreshold:
                        self.callback(bt_addr, rssi, packet, dec, smoothRSSI)
                return
            except:
                pass
        elif (self.unknown):
            bt_addr = pkt[0]
            rssi = int(pkt[2])

            # strip bluetooth address and parse packet
            packet = pkt[1]
            smoothRSSI = self.rHistory(bt_addr, rssi)
            if smoothRSSI >= self.rssiThreshold:
                    self.callback(bt_addr, rssi, packet, dec, smoothRSSI)
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
