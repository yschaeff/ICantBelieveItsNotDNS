import machine
import time, sys
import socket
import micropython as u

## This creates a wifi connection with
## any of our know access points
import net_utils
from trusted_networks import NETWORKS
net_utils.connect_to_ap(NETWORKS)

## Open socket.
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
## bind to first IF. Fine I guess.
addr = socket.getaddrinfo('0.0.0.0', 53)[0][-1]
s.bind(addr)

while 1: #while not recv packet of death ;)
    try:
        m, addr = s.recvfrom(1024)
        #print("rcv pkt, sending to", str(addr), repr(addr))
        s.sendto(m, addr)
    except OSError as e:
        print("OSError: {0}".format(e))
        ## if the query rate is too high the ESP can't keep up
        ## sleep for a bit and hope for better times
        time.sleep(2)
    except Exception as e:
        print("Exception: {0}".format(e), type(e))
