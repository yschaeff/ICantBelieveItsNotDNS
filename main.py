import socket
from time import sleep
from machine import reset

STAT_NOERR = 0
STAT_REFUSED = 5

TYPE_AXFR = 252

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

def create_msg(qid, rr):
    msg = encode_bigendian(qid, 2)      # id
    msg += encode_bigendian((1<<5), 2)  # flags
    msg += encode_bigendian(1, 2)       # 1 query
    msg += encode_bigendian(0, 6)       # empty other sections
    return msg + rr

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
        qu_count = decode_bigendian(self.sock.read(2))
        an_count = decode_bigendian(self.sock.read(2))
        au_count = decode_bigendian(self.sock.read(2))
        ad_count = decode_bigendian(self.sock.read(2))
        self.counts = [qu_count, an_count, au_count, ad_count]
        return self

    def __next__(self):
        for i, c in enumerate(self.counts):
            if c != 0: break
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

def open_axfr(master, zone):
    print("Requesting AXFR for", zone, "from", master)
    axfr_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    axfr_sock.connect((master, 53))
    m = create_msg(42, make_query_rr(zone, TYPE_AXFR, 1))
    m = encode_bigendian(len(m), 2) + m #we need len for TCP.
    axfr_sock.sendall(m)
    axfr_sock.read(2) #aint nobody got mem for that.
    return axfr_sock

def axfr(master, zone):
    ## an AXFR might be very big. We can just return all
    ## we must process on the fly.
    axfr_sock = open_axfr(master, zone)
    qid = decode_bigendian(axfr_sock.read(2))
    flags = decode_bigendian(axfr_sock.read(2))
    return RRiter(axfr_sock)

def axfr_reslv_ptrs(master, zone, ptrs, ptrs_to_reslv):
    axfr_sock = open_axfr(master, zone)
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
    if rr[0] != 1: #from ans section only
        return False
    if decode_bigendian(rr[3]) != 1: #only IN allowed
        return False
    qtype = decode_bigendian(rr[2])
    return not (qtype in [46, 47, 48, 50, 51]) #no dnssec

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

def pop_db(host, zone):
    try:
        axfr_iter = axfr(host, zone)
    except OSError as e:
        print("OSError: {0}, rebooting".format(e))
        sleep(5)
        reset()

    ## we will now resolve compression ptrs by doing a axfr!
    db = {}
    to_resolve = {}
    ptrs = {}
    ptrs_reslv = set()


    for rr in filter(weedwacker, axfr_iter):
        _, qowner, qtype, _, _, rdata = rr
        name, done = uncompress(qowner, ptrs, ptrs_reslv)
        if done:
            db[(name, qtype)] = rdata
        else:
            to_resolve[(name, qtype)] = rdata

    while ptrs_reslv:
        axfr_reslv_ptrs(host, zone, ptrs, sorted(list(ptrs_reslv)))
        for p in ptrs.keys():
            if p in ptrs_reslv:
                ptrs_reslv.remove(p)

        for k,v in to_resolve.items():
            name, done = uncompress(k[0], ptrs, ptrs_reslv)
            if done:
                db[(name, k[1])] = v
                to_resolve.pop(k)

    return db

#db = pop_db("10.0.0.10", "schaeffer.tk")
db = pop_db("83.162.28.200", "schaeffer.tk")
for rr in db:
    print(rr[0], decode_bigendian(rr[1]))

#Open UDP socket.
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#bind to first IF. Fine I guess.
s.bind(socket.getaddrinfo('0.0.0.0', 53)[0][-1])

from webrepl import start
start()

while 1: #while not recv packet of death ;)
    try:
        m, addr = s.recvfrom(1024)
        #print("rcv pkt, sending to", str(addr), repr(addr))
        # find qname, from 
        end = 12
        while m[end] != 0:
            end += m[end] + 1
        qname = m[12:end+1]
        # find qtype
        qtype = m[end+1:end+3]
        # now steal first 12 + (end-12) + 4 bytes of msg
        # set response code and append RR 
        resp = bytearray(m[:end+5])
        resp[2] = (resp[2]&0x01)|0x84 # is reply
        resp[3] &= 0x10
        rdata = db.get((qname, qtype))
        if not rdata: #look for cname then
            rdata = db.get((qname, b'\x00\x05'))
            qtype = b'\x00\x05'
        if not rdata: #NXD
            resp[3] |= 0x03 # NXD
        else:
            resp[7] = 0x01 #always 1 anser
            resp += b'\xC0\x0C' #always point to question for qname
            resp += qtype
            resp += b'\x00\x01' # IN
            resp += b'\x00\x00\x03\x84' #900S TTL
            resp += rdata
        for i in range(8, 12): # no other records
            resp[i] = 0
        s.sendto(resp, addr)
    except OSError as e:
        print("OSError: {0}".format(e))
        ## if the query rate is too high the ESP can't keep up
        ## sleep for a bit and hope for better times
        sleep(2)
    except Exception as e:
        print("Exception: {0}".format(e), type(e))
