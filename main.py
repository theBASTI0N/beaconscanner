import time
from scanner import BeaconScanner
import sys
import time
from uptime import uptime
import datetime
import json
import paho.mqtt.client as mqtt
import ssl
from config import CONFIG as CONFIG
import threading


def getMAC(interface='eth0'):
  # Return the MAC address of the specified interface
  try:
    str = open('/sys/class/net/%s/address' %interface).read()
  except:
    str = "00:00:00:00:00:00"
  return str[0:17]
DEVmac = getMAC(CONFIG.get('interface'))
DEVmac = str.upper(DEVmac.translate({ord(':'): None}))

mFen = CONFIG.get('macFilterEn')
mF = CONFIG.get('macFilter')
RSSIen = CONFIG.get('rssiEn')
RSSI = CONFIG.get('rssi')
TLM = CONFIG.get('tlm')
RUUVI = CONFIG.get('ruuvi')
UNKNOWN = CONFIG.get('unknown')

TOPIC = CONFIG.get('topic1') + "/" + DEVmac + "/" + CONFIG.get('topic2') + "/"
print("Main Topic: " + TOPIC)

DISCONNECTED = 0
CONNECTING = 1
CONNECTED = 2
if CONFIG.get('ssl'):
    ROOT_CA = CONFIG.get('ca')
    CLIENT_CERT = CONFIG.get('cert')
    PRIVATE_KEY = CONFIG.get('key')

def on_message(mosq, obj, msg):
    # This callback will be called for messages that we receive that do not
    # match any patterns defined in topic specific callbacks, i.e. in this case
    # those messages that do not have topics $SYS/broker/messages/# nor
    # test/#
    #print(msg.topic + " " + str(msg.qos) + " " + str(msg.payload))
    pass


def timestamp():
    return '{:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now())

def heartbeat():
    print("Heartbeat Started")
    while 1:
        try:
            m = {}
            ts = str(timestamp())
            ts = ts.translate({ord(' '): 'T'})
            ts = ts + "Z"
            up = round(uptime())
            m = {'ts' : ts,'edgeMAC' : DEVmac,'uptime': up}
            msgJson = json.dumps(m)
            mqttc.publish( CONFIG.get('topic1') + "/" + DEVmac + "/heartbeat", msgJson, qos=0, retain=False )
            time.sleep(30)
        except:
            pass



def callback(bt_addr, rssi, packet, dec):
    if (RUUVI and dec['f'] == 3) or (RUUVI and dec['f'] == 5) or (TLM and dec['f'] == 1) or (UNKNOWN and dec['f'] == 0): 
        if RSSIen:
            if rssi >= RSSI :
                if mFen == True:
                    for i in mF:
                        if str.upper(i) == bt_addr:
                            msg = dec
                            msg['edgeMAC'] = DEVmac
                            msg['data'] = packet
                            msg['rssi'] = rssi
                            ts = str(timestamp())
                            ts = ts.translate({ord(' '): 'T'})
                            ts = ts + "Z"
                            msg['ts'] = ts
                            msgJson = json.dumps(msg)
                            clientBLE.publish( TOPIC + bt_addr, msgJson, qos=0, retain=False )
                else:
                    msg = dec
                    msg['edgeMAC'] = DEVmac
                    msg['data'] = packet
                    msg['rssi'] = rssi
                    ts = str(timestamp())
                    ts = ts.translate({ord(' '): 'T'})
                    ts = ts + "Z"
                    msg['ts'] = ts
                    msgJson = json.dumps(msg)
                    clientBLE.publish( TOPIC + bt_addr, msgJson, qos=0, retain=False )
        else:
            if mFen == True:
                    for i in mF:
                        if str.upper(i) == bt_addr:
                            msg = dec
                            msg['edgeMAC'] = DEVmac
                            msg['data'] = packet
                            msg['rssi'] = rssi
                            ts = str(timestamp())
                            ts = ts.translate({ord(' '): 'T'})
                            ts = ts + "Z"
                            msg['ts'] = ts
                            msgJson = json.dumps(msg)
                            clientBLE.publish( TOPIC + bt_addr, msgJson, qos=0, retain=False )
            else:
                msg = dec
                msg['edgeMAC'] = DEVmac
                msg['data'] = packet
                msg['rssi'] = rssi
                ts = str(timestamp())
                ts = ts.translate({ord(' '): 'T'})
                ts = ts + "Z"
                msg['ts'] = ts
                msgJson = json.dumps(msg)
                clientBLE.publish( TOPIC + bt_addr, msgJson, qos=0, retain=False )


def bleMQTT():
    isSSL = CONFIG.get('ssl')
    isUSR = CONFIG.get('usr')
    state = DISCONNECTED
    global clientBLE
    clientBLE = mqtt.Client()
    if isUSR == True:
        clientBLE.username_pw_set(CONFIG.get('user'), password=CONFIG.get('pass'))
    if isSSL == True:
        clientBLE.tls_set(ca_certs=ROOT_CA, certfile=CLIENT_CERT, keyfile=PRIVATE_KEY, cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
    
    while state != CONNECTED:
        try:
            state = CONNECTING
            clientBLE.connect(CONFIG.get('host'), CONFIG.get('port'), 60)
            state = CONNECTED
        except:
            print('Could not establish MQTT connection')
            time.sleep(0.5)
    if state == CONNECTED:
            print('BLE MQTT Client Connected')
    clientBLE.loop_start()

def heartbeatMQTT():
    isSSL = CONFIG.get('ssl')
    isUSR = CONFIG.get('usr')
    state = DISCONNECTED
    global clientH
    clientH = mqtt.Client()
    if isUSR == True:
        clientH.username_pw_set(CONFIG.get('user'), password=CONFIG.get('pass'))
    if isSSL == True:
        clientH.tls_set(ca_certs=ROOT_CA, certfile=CLIENT_CERT, keyfile=PRIVATE_KEY, cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
    while state != CONNECTED:
        try:
            state = CONNECTING
            clientH.connect(CONFIG.get('host'), CONFIG.get('port'), 60)
            state = CONNECTED
        except:
            print('Could not establish MQTT connection')
            time.sleep(0.5)
    if state == CONNECTED:
            print('Heartbeat MQTT Client Connected')
    clientH.loop_start()

def main_loop():
    heartbeatMQTT()
    time.sleep(2)
    h = threading.Thread(target=heartbeat, args=())
    h.start()
    time.sleep(2)
    bleMQTT()
    # scan for all advertisements from beacons with the specified uuid
    global scanner
    scanner = BeaconScanner(callback)
    scanner.start()

if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        scanner.stop()
        clientBLE.loop_stop()
        clientH.loop_stop()
        clientBLE.disconnect()
        clientH.disconnect()
        print("\nExiting application\n")
        # exit the application
        sys.exit(0)