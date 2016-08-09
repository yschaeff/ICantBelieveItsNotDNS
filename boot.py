# This file is executed on every boot (including wake-boot from deepsleep)
import gc

from trusted_networks import NETWORKS

#NETWORKS = {
#    "essid":"password",
#    "essid":"password",
#    "essid":"password"
#}

## This creates a wifi connection with
## any of our known access points
def connect_to_ap(essids, tries=3):
    from network import WLAN, STA_IF
    from time import sleep
    wlan = WLAN(STA_IF)
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

connect_to_ap(NETWORKS)

gc.collect()
