def decode_bigendian(m):
    ## input byte array. Output uint.
    r = 0
    for b in m:
        r = r<<8 | b
    return r

def encode_bigendian(r, l):
    ## r: integer
    ## l: length of bytearray
    ## return bytearray bigendian
    m = []
    for i in range(l):
        m.append(r&0xff)
        r = r>>8
    m.reverse()
    return bytes(m)

def connect_to_ap(essids, tries=3):
    import network
    from time import sleep
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    ## Select only known networks
    ap_list = list(filter(lambda ap: ap[0].decode('UTF-8') in 
            essids.keys(), wlan.scan()))
    ## sort by signal strength
    ap_list.sort(key=lambda ap: ap[3], reverse=True)
    for ap in ap_list:
        essid = ap[0].decode('UTF-8')
        wlan.connect(essid, essids[essid])
        for i in range(5):
            ## this is somewhat crude, we actually have a
            ## wlan.status() we can inspect. oh well...
            if wlan.isconnected():
                return True
            sleep(1)
    return False
