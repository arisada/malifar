#!/usr/bin/env python3

# Utilities functions and generators for the cache files. Cache files are sorted
# optimization tools. The point is to mark the holes in the file so further
# scans may be accelerated and performed linearly.

# MIT License
# see LICENSE for more information
# Copyright (c) 2024 Aris Adamantiadis

import sys
import os
import codecs
import struct
import asyncio
import logging

from hap.build.hap import HAP as hap
from nsec3hash import NSEC3Hash

# cache file format
# header: 
#   domain <fqdn>
#   date <YYYY-MM-DD HH-MM-SS.dddddd>
#   nsec3params 1 1 0 -
# content of file:
# 0x1234567812345678     -> partial hash of record
# hole                   -> unexplored space between records
# virtual 0x1234567812345678 ABCDEFGHIJ
#                        -> partial hash of virtual record for a hole or 
#                           between RRs. A virtual record is a value that
#                           fits but doesn't have an RR

def parse_cache(f):
    """parse a cache file, line by line, an yield the content.
    Consecutive RRs that do not have a hole (solved or not) between
    them will have a hole emited"""
    prev_is_virtual = False
    prev = 0
    for line in f:
        line=line.strip()
        tokens=line.split(' ')
        if tokens[0] in ("domain", "date", "nsec3params"):
            yield tokens
            continue
        if tokens[0] == "virtual" and len(tokens) == 3:
            yield tokens
            prev_is_virtual = True
            continue
        if tokens[0] == "hole":
            # will be emited at the next line
            continue
        value = int(tokens[0], 16)
        if (value == 0):
            continue
        if (value <= prev):
            print(f"Ordering problem for prev={hex(prev)} and value={hex(value)}")
        if not prev_is_virtual:
            yield ("hole", prev, value)
            yield (value,)
        else:
            yield (value,)
            prev_is_virtual = False
        prev=value



def test_parsing(filename):
    with open(filename, "r") as f:
        parser=parse_cache(f)
        for i in parser:
            #print(i)
            pass

class HAPException(Exception):
    pass
class HAPNotFoundException(HAPException):
    pass

class HAPCache():
    HASH_FAST_NSEC3 = hap.HASH_FAST_NSEC3
    HASH_NSEC3 = hap.HASH_NSEC3
    def __init__(self):
        self.ctx = hap()
        self.htype=None

    def set_loglevel(self, level):
        codes = {
            "none": hap.VERBOSITY_NONE,
            "error": hap.VERBOSITY_ERROR,
            "warning": hap.VERBOSITY_WARNING,
            "debug": hap.VERBOSITY_DEBUG
        }
        if isinstance(level, str):
            self.ctx.set_loglevel(codes[level.lower()])
        else:
            self.ctx.set_loglevel(level)
    def load(self, filename):
        rc = self.ctx.load_hap_file(filename)
        self.check_rc(rc)
        self.htype=self.ctx.get_hash()
    def create(self, filename, value_len=16):
        if self.htype is None:
            raise Exception("htype not set")
        self.ctx.set_hash(htype=self.htype)
        rc = self.ctx.prepare_file(filename=filename, value_len=value_len)
        self.check_rc(rc)

    def create_or_load(self, filename, value_len=16):
        if os.access(filename, 0):
            return self.load(filename)
        else:
            return self.create(filename, value_len)
    def get_key_len(self):
        rc = self.ctx.get_key_len()
        return rc
    def get_value_len(self):
        rc = self.ctx.get_value_len()
        return rc
    def set_metadata(self, md):
        self.ctx.set_global_metadata(md)

    def get_metadata(self):
        rc = self.ctx.get_global_metadata()
        return rc
    def add_entry(self, key:bytes, value:str):
        k_hex=key.hex()
        v_hex=bytes(value, "utf-8").hex()
        #print(f"add_entry({k_hex}, {v_hex})")
        rc = self.ctx.add_entry_hex(k_hex, v_hex)
        self.check_rc(rc)
    def dump(self):
        self.ctx.dump()
    def dedup(self):
        n1=self.get_entries_count()
        self.ctx.dedup()
        n2=self.get_entries_count()
        return n1, n2
    def sort(self):
        self.ctx.sort()
    def get_entries_count(self):
        return self.ctx.get_entries_count()
    def get_entry(self, entry:int):
        key = self.ctx.get_entry(entry)
        value = self.ctx.get_value(entry)
        if key is None or value is None:
            raise HAPNotFoundException
        return (codecs.decode(key, "hex"), codecs.decode(value, "hex"))

    def find_entry(self, key:bytes):
        """find the exact value in the file"""
        k_hex=key.hex()
        rc = self.ctx.find_bisect_range_hex(k_hex, len(key)*8, hap.BISECT_EXACT_MATCH)
        self.check_rc(rc)
        return rc
    def find_previous_entry(self, key:bytes):
        """find the exact value in the file"""
        k_hex=key.hex()
        rc = self.ctx.find_bisect_range_hex(k_hex, len(key)*8, hap.BISECT_PREVIOUS_MATCH)
        self.check_rc(rc)
        return rc
    def __contains__(self, key):
        try:
            x = self.find_entry(key)
            return True
        except HAPNotFoundException:
            return False

    def check_rc(self, rc):
        if rc == hap.ERROR:
            raise HAPException()
        if rc == hap.NOT_FOUND:
            raise HAPNotFoundException()

class HAPFastNSEC3Cache(HAPCache):
    def __init__(self):
        super().__init__()
        self.htype=hap.HASH_FAST_NSEC3

    def add_entry_int(self, key:int, value:str):
        """add an entry in int64 format"""
        k_bytes = struct.pack(">Q", key)
        self.add_entry(k_bytes, value)

    def get_entry(self, entry:int):
        """return an entry in int:str format"""
        k,v = super().get_entry(entry)
        k_int = struct.unpack(">Q", k)[0]
        v_str = str(v.strip(b"\x00"), "ascii")
        return (k_int, v_str)

    def get_entry_int(self, entry:int):
        """return an entry in int:str format"""
        return self.get_entry(entry)

    def has_between(self, a:int, b:int):
        """search for any key between a and b (exclusive) and returns true if
        exists.
        """
        entry=self.get_between(a, b)
        if entry is None:
            return False
        else:
            return True
    def get_previous(self, a:int):
        a_bytes = struct.pack(">Q", a)
        entry = self.find_previous_entry(a_bytes)
        try:
            if entry==0:
                return None
            low = super().get_entry(entry-1)[0]
            low = struct.unpack(">Q", low)[0]
            if low < a:
                return entry-2
            else:
                return entry-1
        except HAPNotFoundException:
            return None

    def get_between(self, a:int, b:int):
        """search for any key between a and b (exclusive) and returns the entry
        if it exists."""
        a_bytes = struct.pack(">Q", a)
        entry = self.find_previous_entry(a_bytes)
        try:
            low = super().get_entry(entry)[0]
            low = struct.unpack(">Q", low)[0]
            if low > a and low < b:
                return entry
        except HAPNotFoundException:
            pass
        
        try:
            high = super().get_entry(entry+1)[0]
            high = struct.unpack(">Q", high)[0]
            if high > a and high < b:
                return entry+1
        except HAPNotFoundException:
            pass

        return None

class HAPNSEC3Cache(HAPCache):
    def __init__(self):
        super().__init__()
        self.htype=hap.HASH_NSEC3
    def create(self, filename):
        super().create(filename, value_len=0)

    def create_or_load(self, filename):
        if os.access(filename, 0):
            return self.load(filename)
        else:
            return self.create(filename)
    def load(self, filename):
        super().load(filename)
        assert(self.htype==hap.HASH_NSEC3)

    def add_entry(self, key:NSEC3Hash):
        assert(len(key.h_bytes)==20)
        super().add_entry(key.h_bytes, '')

    def get_entry(self, entry:int):
        """return an entry in NSEC3Hash format"""
        k,v = super().get_entry(entry)
        return NSEC3Hash(k)

    def find_entry(self, key:NSEC3Hash):
        """find the exact value in the file"""
        return super().find_entry(key.h_bytes)

class MemCache():
    """Memory cache for a FastNSEC3Cache object"""
    def __init__(self, cache):
        self.cache = cache
        self.resolved = {}
        self.unresolved = set()
        self.blocklisted = set()
        self.lock = asyncio.Lock()
        self.toflush = 0
    
    async def find_cache(self, h):
        """find entries that have resolved values in the cache.
        Return a fqdn
        """
        if h in self.resolved.keys():
            return self.resolved[h]
        if h in self.unresolved:
            return None
        async with self.lock:
            ent1 = self.cache.get_between(h[0], h[1])
            if ent1 is not None:
                ent2 = self.cache.get_previous(h[1])
                if ent2 is not None and ent2 > ent1:
                    entry=min(ent1+128, ent2-1)
                else:
                    entry=ent1
                #print(ent1, ent2, entry)
                fqdn = self.cache.get_entry_int(entry)[1]
            else:
                self.unresolved.add(h)
                return None
            
        if fqdn in self.blocklisted:
            self.unresolved.add(h)
            return None
        self.resolved[h]=fqdn
        return fqdn
    def block(self, h, fqdn):
        self.blocklisted.add(fqdn)
        if h in self.resolved.keys():
            self.resolved.pop(h)
    async def add_entry(self, key, value):
        if value in self.blocklisted:
            logging.info(f"Trying to add blocked value {value}")
            return
        async with self.lock:
            self.cache.add_entry_int(key=key, value=value)
        self.toflush += 1
        for h in self.unresolved:
            if h[0] <= key and key < h[1]:
                self.unresolved.remove(h)
                self.resolved[h]=value
                break
        else:
            logging.error(f"qint {hex(key)} fqdn {value} not in unresolved set")
            # force flush ?
            await self.sort_cache()
    
    async def sort_cache(self):
        async with self.lock:
            await asyncio.get_event_loop().run_in_executor(None, self.cache.dedup)
        self.toflush = 0

    async def periodic_flush(self, holes_range, params):
        if self.toflush > 8192:
            await self.sort_cache()
        if len(self.resolved) > 2*len(holes_range) or len(self.resolved) > len(holes_range) + 1000:
            toremove = []
            for h, fqdn in self.resolved.items():
                qint = NSEC3Hash.hash(fqdn, params).qint
                if not holes_range.is_in_range(qint):
                    toremove.append(h)
            for h in toremove:
                self.resolved.pop(h)

    def evict_entry(self, h_from, h_to):
        # make a list of the "big" holes for which the interval is contained
        to_evict=[k for k in self.resolved.keys() if h_from >= k[0] and h_to <= k[1]]
        logging.debug(f"evict_entry ({h_from}, {h_to}) -> {to_evict}")
        if len(to_evict) != 1:
            logging.info(f"evict_entry({hex(h_from)}, {hex(h_to)}): expected 1 match" + str([(hex(a), hex(b)) for a,b in to_evict]))
            #let's evict the smallest one
        if len(to_evict) > 1:
            sizes = [b-a for b,a in to_evict]
            idx = sizes.index(min(sizes))
            to_evict=(to_evict[idx],)
        for i in to_evict:
            del self.resolved[i]

    def stats(self):
        return f"resolved:{len(self.resolved)} unresolved:{len(self.unresolved)} blk:{len(self.blocklisted)} buf:{self.toflush}"

if __name__=="__main__":
    test_parsing(sys.argv[1])
