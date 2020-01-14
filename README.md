# beaconscanner
BLE Scanner for Linux

This application is designed to turn your PC running Linux into a functioning BLE
gateway. It creates a topic that is specific to each tag for ease of
subscribing and using the data.

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