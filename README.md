# pybluez2mqtt
BLE Scanner for Linux

This application is designed to turn your PC running Linux into a functioning BLE
gateway. It creates a topic that is specific to each tag for ease of
subscribing and using the data.

# Installation


```bash
# install libbluetooth headers and libpcap2
sudo apt-get install python3-bluez libbluetooth-dev libcap2-bin
# grant the python executable permission to access raw socket data
sudo setcap 'cap_net_raw,cap_net_admin+eip' $(readlink -f $(which python))
```