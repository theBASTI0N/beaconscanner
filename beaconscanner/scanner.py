"""Classes responsible for Beacon scanning."""
import threading
import struct
from uptime import uptime
from importlib import import_module
from binascii import hexlify
from beacondecoder import decode
from .device_filters import DeviceFilter
from .utils import is_packet_type, to_int, bin_to_int, get_mode, bt_addr_to_string
from .const import (ScanType, ScanFilter, BluetoothAddressType,
                    LE_META_EVENT, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE,
                    OCF_LE_SET_SCAN_PARAMETERS, EVT_LE_ADVERTISING_REPORT,
                    MS_FRACTION_DIVIDER)

class BeaconScanner(object):
    """Scan for Beacon advertisements."""

    def __init__(self, callback, bt_device_id=0, rssiThreshold=-999, ruuvi=True, ruuviPlus=False, eddystone=True, ibeacon=True, unknown=True):
        """Initialize scanner."""

        self._mon = Monitor(callback, bt_device_id, rssiThreshold, ruuvi, ruuviPlus, eddystone, ibeacon, unknown)

    def start(self):
        """Start beacon scanning."""
        self._mon.start()

    def stop(self):
        """Stop beacon scanning."""
        self._mon.terminate()


class Monitor(threading.Thread):
    """Continously scan for BLE advertisements."""

    def __init__(self, callback, bt_device_id, rssiThreshold, ruuvi, ruuviPlus, eddystone, ibeacon, unknown):
        """Construct interface object."""
        # do import here so that the package can be used in parsing-only mode (no bluez required)
        self.bluez = import_module('bluetooth._bluetooth')

        threading.Thread.__init__(self)
        self.daemon = False
        self.keep_going = True
        self.callback = callback

        # number of the bt device (hciX)
        self.bt_device_id = bt_device_id
        # RSSI Threshold, if enabled device with lower power will not be sent
        self.rssiThreshold = rssiThreshold
        # list of beacons to monitor
        self.ruuvi = ruuvi
        self.ruuviPlus = ruuviPlus
        # list of packet types to monitor
        self.eddystone = eddystone
        self.ibeacon = ibeacon
        self.unknown = unknown
        # bluetooth socket
        self.socket = None
        # keep track of RSSI values
        self.rssiHistory = {}
        # RSSI history tracker
        self.seen = {}
        #Time beacon was lasst seen
        self.lastSeen = {}
        # once seen more then 10 times
        self.sten = {}

    def run(self):
        """Continously scan for BLE advertisements."""
        self.socket = self.bluez.hci_open_dev(self.bt_device_id)

        filtr = self.bluez.hci_filter_new()
        self.bluez.hci_filter_all_events(filtr)
        self.bluez.hci_filter_set_ptype(filtr, self.bluez.HCI_EVENT_PKT)
        self.socket.setsockopt(self.bluez.SOL_HCI, self.bluez.HCI_FILTER, filtr)

        self.set_scan_parameters()
        self.toggle_scan(True)

        while self.keep_going:
            pkt = self.socket.recv(255)
            event = to_int(pkt[1])
            subevent = to_int(pkt[3])
            if event == LE_META_EVENT and subevent == EVT_LE_ADVERTISING_REPORT:
                # we have an BLE advertisement
                self.process_packet(pkt)
        self.socket.close()

    def set_scan_parameters(self, scan_type=ScanType.ACTIVE, interval_ms=10, window_ms=10,
                            address_type=BluetoothAddressType.RANDOM, filter_type=ScanFilter.ALL):
        """"sets the le scan parameters

        Args:
            scan_type: ScanType.(PASSIVE|ACTIVE)
            interval: ms (as float) between scans (valid range 2.5ms - 10240ms)
                ..note:: when interval and window are equal, the scan
                    runs continuos
            window: ms (as float) scan duration (valid range 2.5ms - 10240ms)
            address_type: Bluetooth address type BluetoothAddressType.(PUBLIC|RANDOM)
                * PUBLIC = use device MAC address
                * RANDOM = generate a random MAC address and use that
            filter: ScanFilter.(ALL|WHITELIST_ONLY) only ALL is supported, which will
                return all fetched bluetooth packets (WHITELIST_ONLY is not supported,
                because OCF_LE_ADD_DEVICE_TO_WHITE_LIST command is not implemented)

        Raises:
            ValueError: A value had an unexpected format or was not in range
        """
        interval_fractions = interval_ms / MS_FRACTION_DIVIDER
        if interval_fractions < 0x0004 or interval_fractions > 0x4000:
            raise ValueError(
                "Invalid interval given {}, must be in range of 2.5ms to 10240ms!".format(
                    interval_fractions))
        window_fractions = window_ms / MS_FRACTION_DIVIDER
        if window_fractions < 0x0004 or window_fractions > 0x4000:
            raise ValueError(
                "Invalid window given {}, must be in range of 2.5ms to 10240ms!".format(
                    window_fractions))

        interval_fractions, window_fractions = int(interval_fractions), int(window_fractions)

        scan_parameter_pkg = struct.pack(
            ">BHHBB",
            scan_type,
            interval_fractions,
            window_fractions,
            address_type,
            filter_type)
        self.bluez.hci_send_cmd(self.socket, OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS,
                                scan_parameter_pkg)

    def toggle_scan(self, enable, filter_duplicates=False):
        """Enables or disables BLE scanning

        Args:
            enable: boolean value to enable (True) or disable (False) scanner
            filter_duplicates: boolean value to enable/disable filter, that
                omits duplicated packets"""
        command = struct.pack(">BB", enable, filter_duplicates)
        self.bluez.hci_send_cmd(self.socket, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, command)

    def process_packet(self, pkt):
        """Parse the packet and call callback if one of the filters matches."""

        # check if this could be a valid packet before parsing
        # this reduces the CPU load significantly
        if  ( self.ruuvi and pkt[19:21] == b"\x99\x04") or \
            (self.ibeacon and pkt[19:23] == b"\x4c\x00\x02\x15") or \
            (self.eddystone and pkt[19:21] == b"\xaa\xfe"):
            bt_addr = bt_addr_to_string(pkt[7:13])
            bt_addr = bt_addr.upper()
            rssi = bin_to_int(pkt[-1])
            # strip bluetooth address and parse packet
            packet = pkt[14:-1]
            packet = hexlify(packet).decode().upper()
            dec = decode(packet, self.ruuviPlus)
            if(dec['dataFormat' != 0]): #Beacon most likely ibeacon or eddstone URL/UID. FIX needed
                smoothRSSI = self.rHistory(bt_addr, rssi)
                if smoothRSSI >= self.rssiThreshold:
                    self.callback(bt_addr, rssi, packet, dec, smoothRSSI)
            return
        elif (self.unknown):
            bt_addr = bt_addr_to_string(pkt[7:13])
            bt_addr = bt_addr.upper()
            rssi = bin_to_int(pkt[-1])
            # strip bluetooth address and parse packet
            packet = pkt[14:-1]
            packet = hexlify(packet).decode().upper()
            smoothRSSI = self.rHistory(bt_addr, rssi)
            dec = {'dataFormat' : 0}
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
        self.toggle_scan(False)
        self.keep_going = False
        self.join()
