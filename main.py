import machine
import time, sys
import socket
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
TYPE_RRSIG = 46
TYPE_NSEC = 47
TYPE_DNSKEY = 48
TYPE_NSEC3 = 50
TYPE_NSEC3PARAM = 51

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

## contract: exactly 0 bytes must be read from name
class RRiter:
    def __init__(self, sock):
        self.sock = sock

    def __iter__(self):
	## seek to answer section
        ## idea: make a next section()
        qu_count = decode_bigendian(self.sock.read(2))
        an_count = decode_bigendian(self.sock.read(2))
        au_count = decode_bigendian(self.sock.read(2))
        ad_count = decode_bigendian(self.sock.read(2))
        self.counts = [qu_count, an_count, au_count, ad_count]
        return self

    def __next__(self):
        for i, c in enumerate(self.counts):
            if c != 0:
                break
        else:
            self.sock.close()
            raise StopIteration

        self.counts[i] -= 1
        name = b''
        while True: #loop per label
            b = self.sock.read(1)
            name += b
            if (ord(b)&0xC0) == 0xC0:
                name += self.sock.read(1)
                break
            if ord(b) == 0x00:
                break
            name += self.sock.read(ord(b)&0x3F)
        qtype = self.sock.read(2)
        qclass = self.sock.read(2)
        ttl = None
        payload = None
        if i != 0:
            ttl = self.sock.read(4)
            payload = self.sock.read(2)
            datalen = decode_bigendian(payload)
            payload += self.sock.read(datalen)
        return i, name, qtype, qclass, ttl, payload

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
    print("Waiting for AXFR reply")
    m = axfr_sock.read(2)
    readlen = decode_bigendian(m)
    print("Recieving", readlen, "bytes")
    qid = decode_bigendian(axfr_sock.read(2))
    flags = decode_bigendian(axfr_sock.read(2))
    return RRiter(axfr_sock)

def axfr_reslv_ptrs(master, zone, ptrs, ptrs_to_reslv):
    print("Requesting AXFR for", zone, "from", master)
    axfr_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    axfr_sock.connect((master, 53))

    m = create_msg(42, TYPE_QUERY, STAT_NOERR, \
            [make_query_rr(zone, TYPE_AXFR, CLASS_IN)], [])
    m = wrap_tcp(m)
    axfr_sock.sendall(m)
    print("Waiting for AXFR reply")
    m = axfr_sock.read(2)
    readlen = decode_bigendian(m)
    print("Recieving", readlen, "bytes")
    i = 0
    while ptrs_to_reslv:
        p = ptrs_to_reslv.pop(0)
        if p < i:
            #we passed it :( unlikely, but possible
            continue
        while i < p:
            axfr_sock.read(1)
            i += 1
        #read labels until 0 or ptr
        name = b''
        while 1:
            b = axfr_sock.read(1)
            i += 1
            if ord(b)&0xC0 == 0xC0:
                ptrs[p] = name + b + axfr_sock.read(1)
                i += 1
                break
            elif ord(b) == 0x00:
                ptrs[p] = name + b
                break
            else:
                name += b + axfr_sock.read(ord(b))
                i += ord(b)
    axfr_sock.close()

def weedwacker(rr):
    # delete !IN RRSIG DNSKEY NSEC NSEC3 NSEC3PARAM
    if rr[0] != 1:
        return False
    if decode_bigendian(rr[3]) != 1: #only IN allowed
        return False
    qtype = decode_bigendian(rr[2])
    if qtype in [TYPE_RRSIG, TYPE_DNSKEY, TYPE_NSEC, TYPE_NSEC3, TYPE_NSEC3PARAM]:
        return False
    return True

def uncompress(qowner, ptrs, ptrs_reslv):
    # tries to uncompress name. return name. else return null and add to ptrs
    name = b''
    while 1:
        b = qowner[0]
        if b&0xC0 == 0xC0:
            jmp = ((b&0x3F)<<8) | qowner[1]
            if jmp in ptrs:
                qowner = ptrs[jmp] + qowner[2:]
            else:
                ptrs_reslv.add(jmp)
                return name + qowner, False
        elif b == 0x00:
            return name + chr(b), True
        else:
            name += qowner[0: b+1]
            qowner = qowner[b+1:]

try:
    axfr_iter = axfr("10.0.0.10", "schaeffer.tk")
except OSError as ex:
    print("OSError: {0}".format(e))
    print("Failed to obtain AXFR, rebooting in 5 seconds")
    time.sleep(5)
    machine.reset()

## we will now resolve compression ptrs by doing a axfr!
db = {}
to_resolve = {}
ptrs = {}
ptrs_reslv = set()


for rr in filter(weedwacker, axfr_iter):
    _, qowner, qtype, _, ttl, rdata = rr
    name, done = uncompress(qowner, ptrs, ptrs_reslv)
    if done:
        db[(name, qtype)] = (ttl, rdata)
    else:
        to_resolve[(name, qtype)] = (ttl, rdata)

    #print(rr)

#print(db, to_resolve, ptrs, ptrs_reslv)

while ptrs_reslv:
    axfr_reslv_ptrs("10.0.0.10", "schaeffer.tk", ptrs, sorted(list(ptrs_reslv)))
    for p in ptrs.keys():
        if p in ptrs_reslv:
            ptrs_reslv.remove(p)

    for k,v in to_resolve.items():
        name, done = uncompress(k[0], ptrs, ptrs_reslv)
        if done:
            db[(name, k[1])] = v
            to_resolve.pop(k)

print(db)




#while 1: #while not recv packet of death ;)
    #try:
        #m, addr = s.recvfrom(1024)
        ##print("rcv pkt, sending to", str(addr), repr(addr))
        #s.sendto(m, addr)
        ##parse(m)
    #except OSError as e:
        #print("OSError: {0}".format(e))
        ### if the query rate is too high the ESP can't keep up
        ### sleep for a bit and hope for better times
        #time.sleep(2)
    #except Exception as e:
        #print("Exception: {0}".format(e), type(e))
