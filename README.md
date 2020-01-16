# beaconscanner
BLE Scanner for Linux

![PyPI](https://img.shields.io/pypi/v/beaconscanner?style=flat-square)

This application is designed to turn your PC running Linux into a functioning BLE
scanner.

It works with beacondecoder to deliver decoded ble data for:
Eddystone TLM beacons
Ruuvi RAWv1 beacons
Ruuvi RAWv2 beacons



# Installation

The below example if for a system based on Debian 10which includes devices such as Raspberry Pi's.

```bash
# install libbluetooth headers and libpcap2
sudo apt-get install python3-pip python3-bluez libbluetooth-dev git
# grant the python executable permission to access raw socket data
sudo setcap 'cap_net_raw,cap_net_admin+eip' $(readlink -f $(which python3))
#installl python modules
pip3 install beaconscanner
```

# Based On

This code is based on https://github.com/citruz/beacontools
