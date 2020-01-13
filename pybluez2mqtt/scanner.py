"""Classes responsible for Beacon scanning."""
import threading
import struct
import logging
from importlib import import_module
from binascii import hexlify
from beacon-decoder.decoder import decode

from .device_filters import BtAddrFilter, DeviceFilter
from .utils import is_packet_type, to_int, bin_to_int, get_mode
from .const import (ScanType, ScanFilter, BluetoothAddressType,
                    LE_META_EVENT, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE,
                    OCF_LE_SET_SCAN_PARAMETERS, EVT_LE_ADVERTISING_REPORT,
                    MS_FRACTION_DIVIDER,)


_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)

# pylint: disable=no-member,too-many-arguments


class BeaconScanner(object):
    """Scan for Beacon advertisements."""

    def __init__(self, callback, bt_device_id=0, device_filter=None, packet_filter=None):
        """Initialize scanner."""
        # check if device filters are valid
        if device_filter is not None:
            if not isinstance(device_filter, list):
                device_filter = [device_filter]
            if len(device_filter) > 0:
                for filtr in device_filter:
                    if not isinstance(filtr, DeviceFilter):
                        raise ValueError("Device filters must be instances of DeviceFilter")
            else:
                device_filter = None

        # check if packet filters are valid
        if packet_filter is not None:
            if not isinstance(packet_filter, list):
                packet_filter = [packet_filter]
            if len(packet_filter) > 0:
                for filtr in packet_filter:
                    if not is_packet_type(filtr):
                        raise ValueError("Packet filters must be one of the packet types")
            else:
                packet_filter = None

        self._mon = Monitor(callback, bt_device_id, device_filter, packet_filter)

    def start(self):
        """Start beacon scanning."""
        self._mon.start()

    def stop(self):
        """Stop beacon scanning."""
        self._mon.terminate()


class Monitor(threading.Thread):
    """Continously scan for BLE advertisements."""

    def __init__(self, callback, bt_device_id, device_filter, packet_filter):
        """Construct interface object."""
        # do import here so that the package can be used in parsing-only mode (no bluez required)
        self.bluez = import_module('bluetooth._bluetooth')

        threading.Thread.__init__(self)
        self.daemon = False
        self.keep_going = True
        self.callback = callback

        # number of the bt device (hciX)
        self.bt_device_id = bt_device_id
        # list of beacons to monitor
        self.device_filter = device_filter
        self.mode = get_mode(device_filter)
        # list of packet types to monitor
        self.packet_filter = packet_filter
        # bluetooth socket
        self.socket = None
        # keep track of Eddystone Beacon <-> bt addr mapping
        self.eddystone_mappings = []

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
        if  ( \
            (pkt[19:23] == b"\x4c\x00\x02\x15") or \
            (pkt[19:21] == b"\x99\x04") or \
            (pkt[19:21] == b"\xaa\xfe")):
            bt_addr = pkt[7:13]
            bt_addr =hexlify(bt_addr).decode().upper()
            rssi = bin_to_int(pkt[-1])
            # strip bluetooth address and parse packet
            packet = pkt[14:-1]
            packet = hexlify(packet).decode().upper()
            dec = decode(packet)
            self.callback(bt_addr, rssi, packet, dec)
            return


    def terminate(self):
        """Signal runner to stop and join thread."""
        self.toggle_scan(False)
        self.keep_going = False
        self.join()
