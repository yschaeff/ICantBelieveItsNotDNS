import machine
import time
import socket
import micropython as u

## This creates a wifi connection with
## any of our know access points
import net_utils
from trusted_networks import NETWORKS
net_utils.connect_to_ap(NETWORKS)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
addr = socket.getaddrinfo('0.0.0.0', 53)[0][-1]
s.bind(addr)
s.listen(1)
i = 0
while 1:
    try:
        cl, addr = s.accept()
        #print(addr)
        #print(cl)
        m = cl.recv(100)
        cl.write(m)
        cl.close()
        #print("free %d"% gc.mem_free(), i)
        #u.mem_info()
        i = i+1
        #time.sleep_ms(50)
        #del cl
        #del addr
        #del m
        #gc.collect()
        #print(m)
        if i > 50:
            time.sleep(2)
            i = 0
    except:
        print("err in network stuffz")
        #machine.reset()
print("hallo wereld")
