beacons = {}
seen = {}

def rssiHistory(mac, rssi):
    if beacons.get(mac) == None:
        seen[mac] = 0
        beacons[mac] = [0] * 10
        beacons[mac][0] = rssi
    else:
        cnt = seen[mac] + 1
        if cnt == 10:
            cnt = 0
        beacons[mac][cnt] = rssi
        seen[mac] = cnt
