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

TYPE_AXFR = 252
CLASS_IN = 1

def create_msg(qid, mtype, rep_code, rr_q, rr_a):
    msg = b''
    msg += encode_bigendian(qid, 2)
    flags = 0 | (mtype<<15) | (1<<5)
    msg += encode_bigendian(flags, 2)
    msg += encode_bigendian(len(rr_q), 2)
    msg += encode_bigendian(len(rr_a), 2)
    msg += encode_bigendian(0, 2)
    msg += encode_bigendian(0, 2)

    for rr in rr_q:
        msg += rr
    for rr in rr_a:
        msg += rr
    return msg

def wrap_tcp(msg):
    # uPy doesn't support endianess yet...
    return encode_bigendian(len(msg), 2) + msg

def name_to_wire(name):
    wire = b''
    for token in name.split('.'):
        wire += bytes(chr(len(token)) + token, 'utf8')
    wire += b'\x00'
    return wire

def make_query_rr(qowner, qtype, qclass):
    return name_to_wire(qowner) + encode_bigendian(qtype, 2) + \
        encode_bigendian(qclass, 2)

def axfr(master, zone):
    ## a AXFR might be very big. We can just return all
    ## we must process on the fly.

    print("Requesting AXFR for", zone, "from", master)
    axfr_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    axfr_sock.connect((master, 53))

    m = create_msg(42, TYPE_QUERY, STAT_NOERR, \
            [make_query_rr(zone, TYPE_AXFR, CLASS_IN)], [])
    m = wrap_tcp(m)
    axfr_sock.sendall(m)
    print("Waiting for AXFR relpy")
    m = axfr_sock.read(2)
    readlen = decode_bigendian(m)
    print("recieving", readlen, "bytes")
    m = axfr_sock.read(100)
    #m = axfr_sock.read(readlen)
    print("XFR done!")
    axfr_sock.close()
    return m

axfr_msg = axfr("10.0.0.10", "schaeffer.tk")

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
