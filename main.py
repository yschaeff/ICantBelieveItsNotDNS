import socket
from time import sleep
from machine import reset

MASTER = "10.0.0.10"
ZONE = "schaeffer.tk"

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

def name_to_wire(name):
    wire = b''
    for token in name.split('.'):
        wire += bytes(chr(len(token)) + token, 'utf8')
    return wire + b'\x00'

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
    m = encode_bigendian(7, 2)      # id
    m += encode_bigendian((1<<5), 2)  # flags
    m += encode_bigendian(1, 2)       # 1 query
    m += encode_bigendian(0, 6)       # empty other sections
    m += name_to_wire(zone) + b'\x00\xFC\x00\x01' # AXFR IN
    axfr_sock.sendall(encode_bigendian(len(m), 2) + m)
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
        axfr_sock.read(p-i)
        i = p
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

def find_ptr(name):
    ## returns value of pointer in name. Or -1 if no pointer.
    i = 0
    while name[i] != 0x00:
        if name[i]&0xC0 == 0xC0:
            return (name[i]&0x3F)<<8 | name[i+1]
        i += name[i] + 1
    return -1

def populate_db(host, zone):
    try:
        axfr_iter = axfr(host, zone)
    except OSError as e:
        print("OSError: {0}, rebooting".format(e))
        sleep(5)
        reset()

    records = []
    for rr in filter(weedwacker, axfr_iter):
        _, qname, qtype, _, _, rdata = rr
        records.append([qname, qtype, rdata, 0])

    resolved = False
    ptrs = {}
    reslv = set()
    while not resolved:
        for qname, qtype, rdata, _ in records:
            p = find_ptr(qname)
            if p != -1:
                reslv.add(p)
            if qtype == b'\x00\x05':
                p = find_ptr(rdata[2:])
                if p != -1: #CNAME
                    reslv.add(p)
        axfr_reslv_ptrs(host, zone, ptrs, sorted(list(reslv)))
        resolved = True
        for rr in records:
            if rr[3]: continue
            n, rdy = uncompress(rr[0], ptrs, reslv)
            rr[0] = n
            rr[3] = rdy
            resolved &= rdy
            if rr[1] == b'\x00\x05':
                n, rdy = uncompress(rr[2][2:], ptrs, reslv)
                rr[2] = encode_bigendian(len(n), 2) + n
                rr[3] &= rdy
                resolved &= rdy
    db = {}
    for qname, qtype, rdata, _ in records:
        db[(qname, qtype)] = rdata
    return db

db = populate_db(MASTER, ZONE)
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

        # Packet of death:
        #   query, notify
        # We don't want to do any SOA serial management. Nor ACLs or
        # TSIG. Just reboot and retransfer zone.
        if (m[2]&0xF8) == 0x20:
            reset()

        # find qname. Falsely assume this cannot be compressed.
        end = 12
        while m[end] != 0x00:
            end += m[end] + 1
        qname = m[12:end+1]

        # find qtype
        qtype = m[end+1:end+3]

        # now steal first 12 + (end-12) + 4 bytes of msg
        # set response code and append RR
        resp = bytearray(m[:end+5]) #
        resp[2] = (resp[2]&0x01)|0x84 # is reply
        resp[3] &= 0x10 # AD
        for i in range(8, 12): # no auth or additional
            resp[i] = 0

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

        s.sendto(resp, addr)
    except OSError as e:
        print("OSError: {0}".format(e))
        ## if the query rate is too high the ESP can't keep up
        ## sleep for a bit and hope for better times
        sleep(2)
    except Exception as e:
        print("Exception: {0}".format(e), type(e))
