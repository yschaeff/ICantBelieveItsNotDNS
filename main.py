import machine
import time, sys
import socket
import micropython as u
from net_utils import encode_bigendian, decode_bigendian

#Open UDP socket.
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#bind to first IF. Fine I guess.
addr = socket.getaddrinfo('0.0.0.0', 53)[0][-1]
s.bind(addr)

TYPE_QUERY=0
TYPE_REPLY=1

STAT_NOERR = 0
STAT_REFUSED = 5

def create_msg(qid, mtype, rep_code, rr_q, rr_a):
    msg = b''
    msg += encode_bigendian(qid, 2)
    flags = 0 | (mtype<<15) | (1<<5)
    msg += encode_bigendian(flags, 2)
    msg += encode_bigendian(len(rr_q), 2)
    msg += encode_bigendian(len(rr_a), 2)
    msg += encode_bigendian(0, 2)
    msg += encode_bigendian(0, 2)

    sch = 0x0973636861656666657202746b0000fc0001
    msg += encode_bigendian(sch, 18)
    return msg

def wrap_tcp(msg):
    # uPy doesn't support endianess yet...
    return encode_bigendian(len(msg), 2) + msg

zones = ["schaeffer.tk"]
master = "10.0.0.10"
axfr_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
axfr_sock.connect((master, 53))

m = create_msg(42, TYPE_QUERY, STAT_NOERR, [""], [])
m = wrap_tcp(m)
print("sending...", list(map(hex, m)))
axfr_sock.sendall(m)
print("recv...")
m = axfr_sock.read(2)
readlen = decode_bigendian(m)
m = axfr_sock.read(readlen)
print("XFR DONE!")
#print("DATA:", m)
axfr_sock.close()

#def parse(msg):
    #qid = msg[0]<<8 | msg[1]
    #qflags = msg[2]<<8 | msg[3]
    #qcount = msg[4]<<8 | msg[5]
    #qcount = msg[4]
    #print(qid)
    #print(msg)

#def handle(msg, addr):

    
    
    
while 1: #while not recv packet of death ;)
    try:
        m, addr = s.recvfrom(1024)
        #print("rcv pkt, sending to", str(addr), repr(addr))
        s.sendto(m, addr)
        #parse(m)
    except OSError as e:
        print("OSError: {0}".format(e))
        ## if the query rate is too high the ESP can't keep up
        ## sleep for a bit and hope for better times
        time.sleep(2)
    except Exception as e:
        print("Exception: {0}".format(e), type(e))
