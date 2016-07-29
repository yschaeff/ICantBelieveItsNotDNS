def connect_to_ap(essids, tries=3):
    import network, time
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    ## Select only known networks
    ap_list = list(filter(lambda ap: ap[0].decode('UTF-8') in 
            essids.keys(), wlan.scan()))
    ## sort by signal strength
    ap_list.sort(key=lambda ap: ap[3], reverse=True)
    for ap in ap_list:
        essid = ap[0].decode('UTF-8')
        print("ConnectING to AP %s"%essid)
        wlan.connect(essid, essids[essid])
        tries = 5
        for i in range(tries):
            ## this is somewhat crude, we actually have a
            ## wlan.status() we can inspect. oh well...
            if wlan.isconnected(): break
            time.sleep(1)
        if wlan.isconnected():
            print("Connected to AP %s"%essid)
            break
