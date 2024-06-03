#!/usr/bin/env python3

# MIT License
# see LICENSE for more information
# Copyright (c) 2024 Aris Adamantiadis

from Crypto.Hash import SHA
import codecs
import timeit
import os
import sys
import struct
import numpy as np
import pyopencl as cl
import math
import base32hex
import time

SHA1_DIGEST_LEN=20

class NSEC3Params():
    def __init__(self, domain, params=None, hashtype="sha1", flags=None,
        iterations=None, salt=None):
        self.domain=domain
        if(params):
            self.hashtype=int(params[0])
            self.flags = int(params[1])
            self.iterations = int(params[2])
            self.salt = params[3]
            if(self.salt == '-'):
                self.salt = b""
            else:
                self.salt = codecs.decode(self.salt, "hex")
        else:
            if iterations is None:
                raise ValueError("iterations parameter required")
            self.hashtype={"sha1":1}[hashtype]
            self.flags=flags
            self.iterations=iterations
            self.salt=salt if not None else b""
    def serialize(self):
        return " ".join((self.domain, str(self.hashtype), str(self.flags), 
            str(self.iterations), self.salt.hex()))
    def __str__(self):
        return self.serialize()
    def __eq__(self, b):
        return (self.hashtype, self.iterations, self.salt) == (b.hashtype, b.iterations, b.salt)
    @classmethod
    def from_serial(cls, values):
        values=values.split(" ")
        domain=values[0]
        params=values[1:]
        params[0]=int(params[0])
        params[1]=int(params[1])
        params[2]=int(params[2])
        return NSEC3Params(domain=domain, params=params)

class NSEC3Hash():
    def __init__(self, h_bytes):
        self.h_bytes = h_bytes
        self.qint = struct.unpack(">Q", h_bytes[:8])[0]
    def __str__(self):
        return self.h_bytes.hex()
    def __gt__(self, b):
        return self.qint > b.qint
    def __eq__(self, b):
        return self.h_bytes == b.h_bytes
    def b32(self):
        return base32hex.b32encode(self.h_bytes).lower()

    @classmethod
    def by_b32(cls, h):
        hexa = bytes(base32hex.b32decode(h.lower()))
        return NSEC3Hash(hexa)
    @classmethod
    def hash(cls, fqdn, params):
        hexa = hash_raw(fqdn, params)
        return NSEC3Hash(hexa)

def hash_raw(fqdn, params):
    """Hash a domain name according to RFC5155 section 5"""
    x = prehash(fqdn)
    r = x
    H={1:SHA.SHA1Hash}[params.hashtype]
    for i in range(params.iterations + 1):
        r = H(r + params.salt).digest()
    return r

def prehash(fqdn):
    fqdn = fqdn.lower()
    domains = bytes(fqdn, "ascii").strip(b'.').split(b'.')
    x = b''
    for i in domains:
        x += bytes((len(i),))
        x += i
    # ending nul byte
    x += bytes(1)
    return x    

def hash(fqdn, params):
    r = hash_raw(fqdn, params)
    return base32hex.b32encode(r).lower()

# def hash(salt, fqdn, iterations, H=SHA.SHA1Hash):
#     r = hash_raw(salt, fqdn, iterations, H)
#     return base32hex.b32encode(r).lower()

def antihash(h):
    """convert a to-be-hashed binary blob into fqdn"""
    ptr = 0
    fqdn = b""
    domains = []
    while(ptr < len(h)):
        s = h[ptr]
        if s != 0:
            domains.append(h[ptr+1:ptr+1+s])
        ptr += s + 1
    return str(b'.'.join(domains), "ascii")

"""
; <<>> DiG 9.10.3-P4-Ubuntu <<>> +dnssec zzererezer.fr @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 14389
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 8, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 512
;; QUESTION SECTION:
;zzererezer.fr.         IN  A

;; AUTHORITY SECTION:
fr.         3501    IN  SOA nsmaster.nic.fr. hostmaster.nic.fr. 2225043130 3600 1800 3600000 5400
fr.         5301    IN  RRSIG   SOA 8 1 172800 20180517124004 20180318114004 50364 fr. FjOej3NHNjcKsZMeIiIF+rekrAevfVt5EO/ZyCX4Os23E5y/yfv5zdRg +/ndqsLa1CGi8lkaiqHDnNlsl5hJTGu73PSlRxjiVZbHOap4xFi2v0MP SSQEXOBEQ7v4nxUaiLJCKKPhM8dvgbcde9DO2aw5xOMtbAVi+rsFwGxW 7mA=
1QL8O4QD0QIL0LC26D6NPPUV889GM04R.fr. 1027 IN NSEC3 1 1 1 F3A72438 1QLBQ8M4EBBSRIGRN3T5896VQ40ICA4A NS SOA TXT NAPTR RRSIG DNSKEY NSEC3PARAM
1QL8O4QD0QIL0LC26D6NPPUV889GM04R.fr. 1027 IN RRSIG NSEC3 8 2 5400 20180512151953 20180313151953 50364 fr. Vhj8pmV5n6D814TSR4otFmVe7kbuYSnxBF7ukoHrTsUISSqoUVyc/tK7 L5tton0NJaf6HCo8iSr+wHwbjgvuN8oj/ZEOebbYGCgbP8FIHnjSLZwT M7FX+VZl5rWfvZbZ6ULyUbIanmA0gktREP1IFWl09IC66i/MjO8FByMK s2I=
NTV9Q5JPREFSA1PQG0355KQKAI7RBR49.fr. 5400 IN NSEC3 1 1 1 F3A72438 NTVOQC3SNTETQICBUK7GIJ7131210IR3 NS DS RRSIG
NTV9Q5JPREFSA1PQG0355KQKAI7RBR49.fr. 5400 IN RRSIG NSEC3 8 2 5400 20180512151953 20180313151953 50364 fr. BbZnC04PWp68N2PZO76mbb0/7GMn6GJInU2MCLRugNjAjf1ksjBHJmBp kIWdltn5acThZFSiJyCCteZXkb/PTV9VhVgcXD8BMa8sVlZkj+KyIndb cIz79N/si0yTBso1qe9d3wNoFWkgiqavjpxWwsdU+LYS+qlFAvf2bmDi nUU=
64MP6UNTGVE5Q8S0SD58QGG0VAIULHPC.fr. 2252 IN NSEC3 1 1 1 F3A72438 64N913GDRKB9KKIBIJ6UP85M1AD4PH09 NS DS RRSIG
64MP6UNTGVE5Q8S0SD58QGG0VAIULHPC.fr. 2252 IN RRSIG NSEC3 8 2 5400 20180512151953 20180313151953 50364 fr. oUbMPllEvvi5Jj6wLDkByCEkVo+1ya4Q3JfScSNxyNq2lFfSTvProL1i 1xnkWNGbnc1hGrSusbPu7nMd3hY2CkWDEykufFLb/PjJu1Om5SeKwLCH JAkxMUsll+UkO4n41GKdrIjGDhH9Y1bAzc4sQMy5+PobgqjZJdW5NXNk dMA=
"""

def align32(v):
    return v + 4-((v-1)%4)-1

class CLHash():
    def __init__(self, data_max_len, salt_max_len, nthreads):
        self.nthreads = nthreads
        self.data_max_len = max(20, align32(data_max_len))
        #print(f"data_max_len:{self.data_max_len}")
        self.salt_max_len = max(4, align32(salt_max_len))
        self.in_data_size = self.data_max_len * (nthreads+1)
        self.in_salt_size = self.salt_max_len
        self.out_buffer_size = SHA1_DIGEST_LEN * nthreads
        print("Memory estimation: ", (self.in_data_size + self.in_salt_size + self.out_buffer_size)/(1024*1024), "M")

    def prepare(self):
        self.kernel_code = ""
        self.kernel_code += f"#define DATA_MAX_LEN {self.data_max_len}\n"
        self.kernel_code += f"#define SALT_MAX_LEN {self.salt_max_len}\n"
        kernel_file = os.path.dirname(os.path.realpath('__file__')) + "/nsec3hash.cl"
        with open(kernel_file, "r") as f:
            self.kernel_code += f.read()
        self.ctx = cl.create_some_context(answers=[0])
        #platform = cl.get_platforms()[0]
        #device = platform.get_devices()[0]
        #has_64bit_int = cl.device_info.LONG_LONG_ATOMIC in device.get_info(cl.device_info.EXTENSIONS)
        #print(f"64 bit ints support: {has_64bit_int}")
        self.queue = cl.CommandQueue(self.ctx)
        #print("Compiling...")
        self.prg = cl.Program(self.ctx, self.kernel_code).build()
        #print("Success")
        mf = cl.mem_flags
        self.in_data=bytearray(self.in_data_size)
        self.in_salt=bytearray(self.in_salt_size)
        self.out_buffer=bytearray(self.out_buffer_size)

        self.in_data_cl= cl.Buffer(self.ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=self.in_data)
        self.in_salt_cl= cl.Buffer(self.ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=self.in_salt)
        self.out_buffer_cl= cl.Buffer(self.ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=self.out_buffer)

    def sha1(self, data, salt):
        return self.nsec3hash(data, salt, 0)

    def nsec3hash(self, data, salt, iterations):
        self.in_data[:len(data)] = data
        self.in_salt[:len(salt)] = salt

        cl.enqueue_copy(self.queue, self.in_data_cl, self.in_data)
        cl.enqueue_copy(self.queue, self.in_salt_cl, self.in_salt)

        self.prg.nsec3hash(self.queue, (1,), None, self.in_data_cl, self.in_salt_cl, self.out_buffer_cl, np.int32(len(data)), np.int32(len(salt)), np.int32(iterations))
        cl.enqueue_copy(self.queue, self.out_buffer, self.out_buffer_cl)
        return self.out_buffer[:SHA1_DIGEST_LEN]

    def set_salt(self, salt):
        self.in_salt[:len(salt)] = salt
    def set_data(self, data, index):
        #print(len(self.in_data), index, self.nthreads)
        self.in_data[self.data_max_len * index:self.data_max_len * index + len(data)] = data
        #print(len(self.in_data), index)
    def get_data(self, datalen, index):
        return self.in_data[self.data_max_len * index:self.data_max_len * index + datalen]
    def get_hash(self, index):
        return self.out_buffer[SHA1_DIGEST_LEN*index:SHA1_DIGEST_LEN*(index+1)]
    def do_nsec3hash(self, datalen, saltlen, iterations):
        cl.enqueue_copy(self.queue, self.in_data_cl, self.in_data)
        cl.enqueue_copy(self.queue, self.in_salt_cl, self.in_salt)

        self.prg.nsec3hash(self.queue, (self.nthreads,), None, self.in_data_cl, self.in_salt_cl, self.out_buffer_cl, np.int32(datalen), np.int32(saltlen), np.int32(iterations))
        cl.enqueue_copy(self.queue, self.out_buffer, self.out_buffer_cl)

def calc_hashrate(start, nthreads):
    now = time.time_ns()
    ns = now - start
    sec = ns * 1e-9
    hps = nthreads / sec
    s = normalize(hps) + "H/s"
    return s
    #return f"{ns} {sec} {hps} {s}"

class HashFinder():
    def __init__(self, tld, salt, iterations, nthreads, max_nholes):
        self.tld=tld
        self.salt=salt
        self.salt_len = len(salt)
        self.iterations = iterations
        self.nthreads=nthreads
        if nthreads > 2**25:
            raise Exception("Too many threads, adjust counters")

        self.max_nholes=max_nholes
        self.data_max_len=1 + 10 + 1 + len(tld) + 1
        self.clhash = CLHash(self.data_max_len, self.salt_len, nthreads)
        #print(self.salt, self.salt_len)
    def prepare(self):
        self.clhash.prepare()
        self.solutions = np.ndarray((self.max_nholes, 1), dtype=np.int32)
        self.holes = np.ndarray((self.max_nholes, 2), dtype=np.uint64)
        mf = cl.mem_flags

        self.solutions_cl = cl.Buffer(self.clhash.ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=self.solutions)
        self.holes_cl = cl.Buffer(self.clhash.ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=self.holes)
        self.prepare_tld()

    def prepare_tld(self):
        """The tld data is prepared as such:
        fyyyyzzzzz.tld.
        with yyy and zzzz being 5x5bits (global) and 5x5 bits (local) counters
        it becomes [10]yyyyyzzzzz[3]tld[0]
        """
        fqdn = "yyyyyzzzzz." + self.tld
        x = prehash(fqdn)
        assert(len(x) == self.data_max_len)
        for i in range(self.nthreads):
            self.clhash.set_data(x, i)
        self.clhash.set_salt(self.salt)

    def avg_holes_complexity(self, nholes):
        avg = 0.0
        m=0.0
        if nholes == 0:
            return (0.0, 0.0)
        for i in range(nholes):
            cplx = (64 - math.log2(self.holes[i][1] - self.holes[i][0]))
            avg += cplx
            m = max(m, cplx)
        return (avg/nholes, m)

    def match_hashes(self, holes, pbar=None, finish=None, bl=None):
        """Fit hashes to a list of (begin,end) holes. Return a list of
        (begin, solution)"""
        nholes = len(holes)
        for (begin, end), i in zip(holes, range(nholes)):
            self.holes[i][0] = begin
            self.holes[i][1] = end
        self.solutions.fill(-1)
        solved = []
        cl.enqueue_copy(self.clhash.queue, self.holes_cl, self.holes)
        cl.enqueue_copy(self.clhash.queue, self.solutions_cl, self.solutions)
        cl.enqueue_copy(self.clhash.queue, self.clhash.in_data_cl, self.clhash.in_data)
        cl.enqueue_copy(self.clhash.queue, self.clhash.in_salt_cl, self.clhash.in_salt)

        # Currently limited to 25 bits counter
        for counter in range(2**25):
            if finish is not None:
                if finish.finished:
                    break
            start=time.time_ns()
            # __kernel void prepare_data_buffer(__global in_data_t *buffer, int data_len, unsigned int counter);
            self.clhash.prg.prepare_data_buffer(
                self.clhash.queue, 
                (self.nthreads,), 
                None, 
                self.clhash.in_data_cl,
                np.int32(self.data_max_len),
                np.uint32(counter)
                )
            #cl.enqueue_copy(self.clhash.queue, self.clhash.in_data, self.clhash.in_data_cl)
            #print(self.clhash.in_data[:200])

            self.clhash.prg.nsec3hash(
                self.clhash.queue, 
                (self.nthreads,), None, 
                self.clhash.in_data_cl, self.clhash.in_salt_cl, 
                self.clhash.out_buffer_cl, np.int32(self.data_max_len), 
                np.int32(len(self.salt)), np.int32(self.iterations)
                )
            # __kernel void match_hash(__global int *solutions, __global outbuffer_t *nsec3_hashes, 
            #                          __global hole_t *holes, int nholes)
            self.clhash.prg.match_hash(
                self.clhash.queue,
                (self.nthreads, ),
                None, 
                self.solutions_cl,
                self.clhash.out_buffer_cl,
                self.holes_cl,
                np.int32(nholes)
                )
            #cl.enqueue_copy(self.clhash.queue, self.clhash.out_buffer, self.clhash.out_buffer_cl)
            cl.enqueue_copy(self.clhash.queue, self.solutions, self.solutions_cl).wait()
            #print(self.clhash.out_buffer[:256])
            # browse the solutions, copy the solutions, remove them from holes_cl
            #print(self.solutions)
            i = 0
            copied = False
            while i < nholes:
                if self.solutions[i] == -1:
                    i+=1
                else:
                    #print("solve ", i, self.solutions[i])
                    if not copied:
                        cl.enqueue_copy(self.clhash.queue, self.clhash.in_data, self.clhash.in_data_cl).wait()
                        copied=True
                    sol = int(self.solutions[i])
                    #print((hex(self.holes[i][0]), hex(self.holes[i][1]), self.clhash.get_data(self.data_max_len, sol), self.clhash.get_hash(sol).hex()))
                    fqdn = antihash(self.clhash.get_data(self.data_max_len, sol))
                    if bl and fqdn in bl:
                        # fqdn is blocked, don't append it
                        print(f"Skip blocked fqdn {fqdn}")
                        # mark it as bad in cl memory so we don't hit on it on next iteration
                        self.solutions[i] = -1
                        cl.enqueue_copy(self.clhash.queue, self.solutions_cl, self.solutions)
                        i += 1
                        continue
                    solved.append([self.holes[i][0], self.holes[i][1], fqdn])
                    nholes -= 1
                    self.holes[i] = self.holes[nholes]
                    self.solutions[i] = self.solutions[nholes]
                    self.holes[nholes] = [0, 0]
            avg, maxi = self.avg_holes_complexity(nholes)
            hashrate=calc_hashrate(start, self.nthreads)
            status=f"spd {hashrate:14s} solved {len(solved):5d}, {nholes:5d} left, avg cplx {avg:0.3f} max {maxi:0.3f}, hashes done: 2**{math.log2((counter+1) * self.nthreads):0.3f}"
            if pbar is not None:
                pbar.set_description(status)
                pbar.update(1)
            else:
                print(status)
            if nholes==0:
                break
            cl.enqueue_copy(self.clhash.queue, self.holes_cl, self.holes)
            cl.enqueue_copy(self.clhash.queue, self.solutions_cl, self.solutions).wait()
            #print(self.holes[:min(nholes, 10)])

        else:
            print(f"Couldn't solve after {counter} iterations")
        solved.sort(key=lambda x:(x[0], x[1]))
        return solved

def test():
    fqdn = "0day.li"
    #salt = b"\xf3\xa7\x24\x38"
    #salt = b"\xaa\xbb\xcc\xdd"
    salt = b""
    #salt=codecs.decode("9F21B3EAFFCA9DB0", "hex")

    print("Hash of %s %s"%(fqdn, salt))
    print(hash(salt=salt, fqdn=fqdn, iterations=0))

def test_simple_sha():
    clhash=CLHash(data_max_len=30, salt_max_len=4, nthreads=64);
    clhash.prepare()
    for j in range(5):
        salt = bytes([0x61 + k for k in range(j)])
        for i in range(30):
            data = bytes([0x42 + k for k in range(i)])
            h=clhash.sha1(data, salt)
            h2 = SHA.SHA1Hash(data + salt).digest()
            print(h.hex(), h2.hex(), data, salt)
            if(h != h2):
                print("Warning, different results !")

def test_nsec3():
    clhash=CLHash(data_max_len=30, salt_max_len=4, nthreads=64);
    clhash.prepare()
    iterations=0
    for j in range(5):
        salt = bytes([0x61 + k for k in range(j)])
        for i in range(30):
            data = bytes([0x42 + k for k in range(i)])
            h=clhash.nsec3hash(bytes([len(data)]) + data + bytes(1), salt, iterations)
            h2 = hash_raw(fqdn=str(data, "ascii"), salt=salt, iterations=iterations)
            print(h.hex(), h2.hex(), data, salt)
            if(h != h2):
                print("Warning, different results !")


"""
dig +dnssec onowtwoe.fr. @193.176.144.22
nexthash rpb4cc3pl7a32jvk9io2o9asqtesf4km rpb7l23at1h55e484m8oejk99csm20h2"""

def average(l):
    return sum(l) / len(l)

def bench_python(fqdn, params, i):
    def sub_hash():
        return hash_raw(fqdn=fqdn, params=params)

    t = timeit.repeat(sub_hash, number=i)
    return average(t)/i

def bench_cl(fqdn, params, i):
    clhash=CLHash(data_max_len=len(fqdn)+2, salt_max_len=len(params.salt), nthreads=i)
    clhash.prepare()

    data = prehash(fqdn)
    saltlen=len(params.salt)
    clhash.set_salt(params.salt)
    for j in range(i):
        clhash.set_data(data, j)

    def sub_hash():
        # data = bytes([len(bench[1])]) + bytes(bench[1], "ascii") + b"\x00"
        # saltlen=len(bench[0])
        # clhash.set_salt(bench[0])
        # for j in range(i):
        #     clhash.set_data(data, j)
        clhash.do_nsec3hash(datalen=len(data), saltlen=saltlen, iterations=params.iterations)
        return None
    t = timeit.repeat(sub_hash, number=1)
    #print(t)
    return average(t)/i

def normalize(v):
    units={3:"K", 0:"", 6:"M", 9:"G", 12:"T", 15:"P", -3:"m", -6:"u", -9:"n", -12:"p"}
    for i in range(18, -18, -3):
        exponent = 10**i
        if v > exponent:
            v = v/exponent
            if i in units.keys():
                return f"{v:.3f}" + " " + units[i]    
            else:
                return f"{v:.3f}e{i}"
    return f"{v}"

def bench():
    fqdn="test.coma"
    iterations=10
    salt=b"ABCDEFGH"
    print(f"benchmarking {fqdn} salt={salt} iterations={iterations}")
    params = NSEC3Params(domain=fqdn, salt=salt, iterations=iterations)
    n = [128, 1024, 4096, 65536, 2**20]
    print("Python (hash/s)")
    python_t=[]
    for i in n[:-2]:
        python_t.append(bench_python(fqdn, params, i))
    print(n[:-1])
    hps = [normalize(1/i) for i in python_t]
    print(hps)
    python_max = max([1/i for i in python_t])
    print("CL (hash/s)")
    cl_t=[]
    for i in n:
        cl_t.append(bench_cl(fqdn, params, i))
    print(n)
    hps = [normalize(1/i) for i in cl_t]
    print(hps)
    cl_max = max([1/i for i in cl_t])
    print("CL speedup: ", cl_max/python_max)

def cmdline():
    args=sys.argv[1:]
    if len(args) < 1 or len(args) > 3:
        print("Usage: %s fqdn [iterations [salt]]"%(sys.argv[0],))
        return
    fqdn = args[0]
    if len(args) > 1:
        iterations = int(args[1])
    else:
        iterations = 0
    if len(args) > 2:
        salt = codecs.decode(args[2], "hex")
    else:
        salt = b''
    params = NSEC3Params(domain=fqdn, iterations=iterations, salt=salt)
    h = hash_raw(fqdn, params)
    b32 = base32hex.b32encode(h).lower()
    print(f"{fqdn}: {b32} {h.hex()}")

def main():
    cmdline()
    #bench()
    #test_simple_sha()
    #test_nsec3()

if __name__=='__main__':
    main()
