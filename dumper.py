#!/usr/bin/env python3

# MIT License
# see LICENSE for more information
# Copyright (c) 2024 Aris Adamantiadis

import asyncio
import argparse
import logging
import random
import traceback
import math
import signal
import os
import time
from datetime import datetime
from sortedcontainers import SortedList
from collections import defaultdict
from munch import DefaultMunch
import tqdm
from fastdns import scanner_coroutine, dns_query, full_query_dnssec
from cache import HAPCache, HAPFastNSEC3Cache, HAPNSEC3Cache, MemCache
from nsec3hash import NSEC3Params, NSEC3Hash
from config import config

class RangeList():
    def __init__(self):
        self.ranges=SortedList()
    def add(self, start, end):
        self.ranges.add((start, end))
        self.coalesce(start, end)

    def coalesce(self, start, end):
        idx = self.get_range_index(start)
        if idx > 0: idx -= 1
        while idx+1 < len(self.ranges):
            a1,b1 = self.ranges[idx]
            if a1 > end:
                break
            a2, b2 = self.ranges[idx+1]
            if b1 >= a2:
                #print(f"coalesce ({a1}, {b1}) - ({a2}, {b2})")
                a = self.ranges.pop(idx)
                b = self.ranges.pop(idx)
                #print(a, b, a1, b2)
                #print(self.ranges)
                self.ranges.add((min(a1, a2), max(b1, b2)))
                #print(self.ranges)
            else:
                idx += 1

    def remove(self, start, end):
        idx = self.get_range_index(start)
        if idx is None: idx = 0
        while idx < len(self.ranges):
            a, b = self.ranges[idx]
            if a > end:
                break
            if start <= a and end >= b:
                self.ranges.pop(idx)
                continue
            if start < b and end >= b:
                self.ranges.pop(idx)
                self.ranges.add((a, start))
                continue
            if start <= a and end > a:
                self.ranges.pop(idx)
                self.ranges.add((end, b))
                continue
            if start > a and end < b:
                self.ranges.pop(idx)
                self.ranges.add((a, start))
                self.ranges.add((end, b))
                continue
            idx += 1

    def is_in_range(self, value):
        return self.get_range_index(value) != None

    def get_range_index(self, value):
        index = self.ranges.bisect_left((value, 2**64))

        if index > 0:
            start, end = self.ranges[index - 1]
            if start <= value <= end:
                return index-1
        return None
    def pop_if_exist(self, value):
        index = self.get_range_index(value)
        if index is not None:
            ret = self.ranges.pop(index)
            return ret
        return None
    def __len__(self):
        return len(self.ranges)
    def __getitem__(self, idx):
        return self.ranges[idx]
    def __eq__(self, b):
        return self.ranges == b.ranges


class DumperStatus():
    maxvalue = int(2**64 - 1)
    def __init__(self):
        self.solved = RangeList()
        self.holes = RangeList()
        self.holes.add(0, self.maxvalue)
        self.nrequests=0

    def __eq__(self, b):
        return self.holes == b.holes and self.solved == b.solved

    def is_solved(self, start, end):
        if self.solved.is_in_range(end) and self.solved.is_in_range(start):
            range = self.solved[self.solved.get_range_index(start)]
            a, b = range
            if start >= a and end <= b:
                return True
        return False

    def add_nsec(self, start, end):
        self.holes.remove(start, end)
        self.solved.add(start, end)

    def print(self, start=0, end=None):
        if end is None:
            end=self.maxvalue
        i = 0
        j = 0
        while i < len(self.holes) or j < len(self.solved):
            if i < len(self.holes):
                h = self.holes[i]
            else:
                h = None
            if j < len(self.solved):
                s = self.solved[j]
            else:
                s = None
            if h is None:
                if s[0] >= start and s[1] <= end:
                    print(f'Solv({s[0]},{s[1]})')
                j+=1
            elif s is None:
                if h[0] >= start and h[1] <= end:
                    print(f'Hole({h[0]},{h[1]})')
                i += 1
            else:
                if s[0] < h[0]:
                    if s[0] >= start and s[1] <= end:
                        print(f'Solv({s[0]},{s[1]})')
                    j += 1
                else:
                    if h[0] >= start and h[1] <= end:
                        print(f'Hole({h[0]},{h[1]})')
                    i += 1
    def get_status(self):
        total = 0
        for a,b in self.solved:
            total += b-a
        return float(total) * 100.0/float(self.maxvalue)

    def check_consistency(self):
        total_holes = 0
        total_solved = 0
        for a,b in self.holes:
            total_holes += b-a
        for a,b in self.solved:
            total_solved += b-a
        if total_holes + total_solved != self.maxvalue:
            logging.error(f"inconsistent dump! {total_holes:x} + {total_solved:x} = " +
                f"{total_solved + total_holes:x}, expected {self.maxvalue:x}")
            self.print()
            raise Exception("Dump corruption")

    def get_holes(self, limit):
        return list(self.holes[:limit])

    def save(self, filename):
        self.check_consistency()
        with open(filename, "w") as f:
            f.write("holes\n")
            for a,b in self.holes:
                f.write(f"{a} {b}\n")
            f.write("solved\n")
            for a,b in self.solved:
                f.write(f"{a} {b}\n")
            f.write("nrequests\n")
            f.write(f"{self.nrequests}\n")

    def load(self, filename):
        self.holes = RangeList()
        with open(filename, "r") as f:
            line = f.readline().strip()
            assert(line=="holes")
            while True:
                line = f.readline().strip()
                if line == "solved":
                    break
                a, b = line.split(" ")
                self.holes.add(int(a),int(b))
            while True:
                line = f.readline().strip()
                if line=="nrequests" or line == '':
                    break
                a, b = line.split(" ")
                self.solved.add(int(a),int(b))
            if line == "nrequests":
                line = f.readline().strip()
                self.nrequests=int(line)
        self.check_consistency()

class TimeCheck():
    def __init__(self, name, maxtime=0.1):
        self.maxtime = maxtime
        self.name = name
    def __enter__(self):
        self.start = time.time_ns()
    def __exit__(self, exc_type, exc_value, exc_tb):
        stop = time.time_ns()
        seconds = (stop - self.start) * 1e-9
        if seconds > self.maxtime:
            logging.warning(f"Timecheck {self.name} took {seconds:0.3f} seconds")

class DumpManager():
    def __init__(self, config, args):
        self.tld = args.tld
        self.args = args
        self.prepare_config(config)
        self.nsec_queue = asyncio.Queue(256)
        self.range_queue = dict()
        self.dumperstatus = DumperStatus()
        self.cache = HAPFastNSEC3Cache()
        self.memcache = MemCache(self.cache)
        self.zonecache = HAPNSEC3Cache()
        self.zone_memcache = set()
        self.solved = 0
        self.cracking = 0 #how many holes sent to cracking service
        self.last_hash = "Initializing"
        self.finished = asyncio.Event()
        self.new_targets = asyncio.Event()
        self.too_complex = set() # holes too complex to be cracked today

    def prepare_config(self, config):
        self.config = DefaultMunch.fromDict(config, None)
        tld_configs = [d for d in self.config.domains if d.name==self.tld]
        if len(tld_configs) == 0:
            logging.warning(f"No configuration for tld {self.tld}")
        else:
            tld_config = tld_configs[0]
            if tld_config.nameservers:
                self.config.nameservers = tld_config.nameservers
            if tld_config.cachefile:
                self.config.cachefile = tld_config.cachefile
            if tld_config.zonefile:
                self.config.zonefile = tld_config.zonefile
            if tld_config.workdir:
                self.config.workdir = tld_config.workdir
            if tld_config.nsec3params:
                self.config.nsec3params = tld_config.nsec3params
            if tld_config.concurrency:
                self.config.concurrency = tld_config.concurrency
            if tld_config.maxreqs:
                self.config.maxreqs = tld_config.maxreqs
            if tld_config.timeout:
                self.config.timeout = tld_config.timeout
        fmt = {
            "tld": self.tld,
            "date": datetime.today().date().isoformat()
        }

        self.config.workdir = self.config.workdir.format(**fmt)
        fmt["workdir"] = self.config.workdir
        self.config.cachefile = self.config.cachefile.format(**fmt)
        self.config.zonefile = self.config.zonefile.format(**fmt)
        self.config.restorefile = self.config.restorefile.format(**fmt)
        if self.args.max_complexity:
            self.config.maxcomplexity = float(self.args.max_complexity)
        if self.config.maxcomplexity < 10:
            logging.error("Complexity not set properly")
            raise Exception("Complexity not set properly")
    def retrieve_dns(self):
        if self.config.nameservers:
            logging.warning("Nameservers pre-configured, not querying")
        else:
            ns=dns_query(self.tld, "NS")
            print(ns)
            ns_ips=[]
            for i in ns:
                A = dns_query(i, "A")
                ns_ips += A
                AAAA = dns_query(i, "AAAA")
                ns_ips += AAAA
            self.config.nameservers = ns_ips
        if self.config.nsec3params:
            self.nsec3params = NSEC3Params.from_serial(self.config.nsec3params)
        else:
            rec = asyncio.run(full_query_dnssec(self.tld, "dheurywn623x." + self.tld))
            params=rec.params
            self.nsec3params = params

    def inner_signal_handler(self, sig, frame):
        self.finished.set()
        #writing here causes troubles
        #logging.warning("Received SIGINT, closing")
        signal.signal(signal.SIGINT, signal.SIG_DFL)

    def scan(self):
        def check_metadata(cache, nsec3params):
            md = cache.get_metadata()
            if md == "Random file data":
                cache.set_metadata(nsec3params.serialize())
                logging.info("Update file metadata to "+ nsec3params.serialize())
            elif md != nsec3params.serialize():
                logging.error("Wrong metadata for this zone!")
                logging.error(md)
                logging.error("Expected: " + nsec3params.serialize())
                raise Exception("Wrong metadata in cache file")

        logging.warning(f"Preparing scanner for **{self.tld}** zone")
        self.retrieve_dns()
        datasize = 11 + len(self.tld)
        self.cache.create_or_load(self.config.cachefile, value_len=datasize)
        check_metadata(self.cache, self.nsec3params)
        self.cache.dedup()
        self.zonecache.create_or_load(self.config.zonefile)
        check_metadata(self.zonecache, self.nsec3params)
        a,b = self.zonecache.dedup()
        if a!=b:
            logging.warning(f"Deduping the file: {a} -> {b} records ({100.0*float(b)/float(a)}%)")
        restorefile=self.config.restorefile
        if self.args.restore:
            logging.warning(f"Restoring from file {restorefile}")
            self.dumperstatus.load(restorefile)
        else:
            if os.access(restorefile, 0)==1:
                logging.error(f"Restore file {restorefile} exists. Delete or run with -c")
                return
        signal.signal(signal.SIGINT, self.inner_signal_handler)
        asyncio.run(self.aio_scan())
        if len(self.dumperstatus.holes) == 0:
            os.unlink(restorefile)
        else:
            logging.warning(f"Write restore file {restorefile}")
            self.dumperstatus.save(restorefile)

    async def aio_scan(self):
        resolvers=[]
        for _ in range (self.config.concurrency):
            resolvers += [scanner_coroutine(ns, self) for ns in self.config.nameservers]
        tasks=[]
        tasks.append(asyncio.create_task(self.prepare_targets()))
        tasks.append(asyncio.create_task(self.cracking_service(hard=False)))
        tasks.append(asyncio.create_task(self.cracking_service(hard=True)))
        tasks.append(asyncio.create_task(self.tqdm_coro()))
        tasks.append(asyncio.create_task(self.save_coro()))
        tasks.append(asyncio.create_task(self.watchdog_coro()))

        await asyncio.gather(*resolvers)
        self.zonecache.dedup()

    def split_holes(self, holes):
        """split the biggest hole in half to improve discovery"""
        if len(holes) == 0 or len(holes) > 16:
            return holes
        #print("before split:", holes)
        sizes = [b-a for a, b in holes]
        idx = sizes.index(max(sizes))
        x, y = holes.pop(idx)
        mid=x + (y-x)//2
        holes.append((x, mid))
        holes.append((mid, y))
        #holes.sort()
        #print("after split:", holes)
        return holes

    async def prepare_targets(self):
        while True:
            if len(self.range_queue) == 0:
                if len(self.dumperstatus.holes) == len(self.too_complex):
                    logging.info("Dumping finished !")
                    if len(self.too_complex) > 0:
                        logging.warning(f"Finishing with {len(self.too_complex)} uncracked holes")
                    self.finished.set()
            if self.finished.is_set():
                logging.warning("Receiving finish signal, terminating...")
                for _ in range(256):
                    await self.nsec_queue.put(None)
                #del self.nsec_queue
                await self.memcache.sort_cache()
                logging.info("end of prepare_targets()")
                return

            holes = []
            logging.debug("prepare_targets")
            start = time.time_ns()
            for h in self.dumperstatus.holes:
                if h not in self.range_queue.keys():
                    holes.append(h)
                if len(holes) > 2048:
                    break

            #holes = self.split_holes(holes)
            #logging.debug("first 64 holes:"+str(holes))
            #print(holes)
            self.new_targets.clear()
            cached = 0
            for h in holes:
                await asyncio.sleep(0)
                fqdn = await self.memcache.find_cache(h)
                    #logging.debug(f"fqdn {fqdn} hole {h} cplx {self.complexity(h)}")
                if fqdn is None:
                    continue
                if self.finished.is_set():
                    break
                if h in self.range_queue.keys():
                    logging.error(f"{h}:{fqdn} already in range_queue (should not happen)")
                    continue
                self.range_queue[h] = fqdn
                logging.debug(f"Adding cached value {h}:{fqdn}")
                await self.nsec_queue.put((fqdn, h))
                cached +=1
            #now is the best time to flush
            await self.memcache.periodic_flush(self.dumperstatus.holes, self.nsec3params)
            if cached == 0:
                logging.debug("Nothing in cache, waiting for cracking thread")
                try:
                    await asyncio.wait_for(self.new_targets.wait(), timeout=0.1)
                except:
                    pass
            #await asyncio.sleep(0.01) ##TODO comprendre d'où vient la race sur range_queue

    def complexity(self, h):
        return 64 - math.log2(h[1] - h[0])

    async def cracking_service(self, hard=False):
        max_complexity=int(self.config.maxcomplexity)
        try:
            host, port = self.config.crackservice.split(":")
            while True:
                try:
                    reader, writer = await asyncio.open_connection(host, port)
                    logging.warning(f"Connected to crackserver {host}:{port}")
                except ConnectionRefusedError as e:
                    print(e)
                    await asyncio.sleep(10)
                    logging.warning("Retrying...")
                    continue
                try:
                    writer.write(bytes(self.nsec3params.serialize() + "\n", "ascii"))
                    await writer.drain()
                except ConnectionResetError:
                    logging.warning("Connection reset when connecting to crackserver. Retrying")
                    writer.close()
                    await writer_wait_closed()
                    await asyncio.sleep(10)
                    continue
                while True:
                    if self.finished.is_set():
                        writer.close()
                        await writer.wait_closed()
                        return
                    holes=[]
                    for h in list(self.dumperstatus.holes.ranges):
                        if h in self.too_complex:
                            continue
                        await asyncio.sleep(0)
                        if (h[0] >= h[1]):
                            logging.error(f"Invalid hole {h}")
                            self.dumperstatus.holes.ranges.remove(h)
                            continue
                        cplx = self.complexity(h)
                        if hard and cplx < 30.0:
                            continue
                        elif not hard and cplx >= 30.0:
                            continue
                        if hard and cplx > max_complexity:
                            logging.warning(f"Hole has complexity {cplx}")
                            self.too_complex.add(h)
                            continue
                        fqdn = await self.memcache.find_cache(h)
                        if fqdn == None:
                            holes.append(h)
                            logging.debug(f"hole {h} NOT in cache (cplx {cplx})")
                        else:
                            logging.debug(f"hole {h} already in cache (cplx {cplx})")
                        if len(holes) > 1023:
                            break
                    if len(holes) == 0:
                        logging.info("Nothing to crack, sleeping...")
                        await asyncio.sleep(0.1)
                    else:
                        logging.debug("Cracking holes:" + str(holes))
                        # check that we don't have weird duplicates
                        #for i in range(len(holes) - 1):
                        #    if holes[i][0] == holes[i+1][0]:
                        #        logging.warning(f"Duplicate holes {holes[i]}, {holes[i+1]}")
                        #        self.dumperstatus.check_consistency()
                        try:
                            if len(self.memcache.blocklisted) != 0:
                                # prevent some domain names from appearing in the results
                                blocked = ",".join(self.memcache.blocklisted)
                                writer.write(bytes("bl " + blocked + "\n", "ascii"))
                            for h in holes:
                                writer.write(bytes(f"{h[0]} {h[1]}\n", "ascii"))
                                self.cracking += 1
                            await writer.drain()
                        except ConnectionResetError:
                            logging.warning("Connection reset when connecting to crackserver. Retrying")
                            writer.close()
                            await writer.wait_closed()
                            await asyncio.sleep(10)
                            continue
                        for _ in range(len(holes)):
                            #print("Waiting for lines")
                            line = await reader.readline()
                            logging.debug(f"crackserver rcv {line.strip()}")
                            if line==b"":
                                logging.warning("Crackserver error, retrying")
                                writer.close()
                                await writer.wait_closed()
                                await asyncio.sleep(10)
                                continue # ca marche pas ça aris...
                            line=str(line, "ascii").strip()
                            a, b, k, v = line.split(" ")
                            k=int(k)
                            logging.debug("Adding:" + str((k, v)))
                            self.cracking -= 1
                            await self.memcache.add_entry(key=k, value=v)

                        self.new_targets.set()
                        await asyncio.sleep(0.1)
                    
                writer.close()
                await writer_wait_closed()
        except Exception as e:
            print("Exception:", e)
            traceback.print_exc()
    def remove_range(self, h):
        if not h in self.range_queue.keys():
            logging.error(f"Value {h} not in the range queue as expected (len={len(self.range_queue)})")
        else:
            x=self.range_queue.pop(h)
            logging.debug(f"remove {x}")
        self.nsec_queue.task_done()
    def evict_cache(self, h, fqdn):
        self.memcache.block(h, fqdn)
    async def next_fqdn(self):
        if self.finished.is_set() and self.nsec_queue.qsize()==0:
            return None
        return await self.nsec_queue.get()
    def add_result(self, h):
        if h in self.zonecache or h.h_bytes in self.zone_memcache:
            pass
        self.zonecache.add_entry(h)
        if len(self.zone_memcache) > 1024:
            self.zone_memcache.clear()
            self.zonecache.dedup()
        else:
            self.zone_memcache.add(h.h_bytes)

    async def tqdm_coro(self):
        last_nrequests = self.dumperstatus.nrequests
        completion = self.dumperstatus.get_status()
        estimated=1000
        with tqdm.tqdm(dynamic_ncols=True, total=estimated, initial=last_nrequests) as pbar:
            while True:
                completion = self.dumperstatus.get_status()
                logging.info(f"State: {completion}%")
                if completion > 0.0001:
                    estimated = int(self.dumperstatus.nrequests * 100/completion)
                pbar.total=estimated
                status_str = f"{self.last_hash} queue:{self.nsec_queue.qsize()} holes:{len(self.dumperstatus.holes)} solved:{len(self.dumperstatus.solved)} range:{len(self.range_queue)} crk:{self.cracking} cplx:{len(self.too_complex)} "
                status_str += self.memcache.stats()
                pbar.set_description(status_str)
                pbar.update(self.dumperstatus.nrequests - last_nrequests)
                last_nrequests = self.dumperstatus.nrequests
                await asyncio.sleep(0.1)
                if self.finished.is_set():
                    break

    async def save_coro(self):
        while not self.finished.is_set():
            logging.info("Saving status")
            self.dumperstatus.save(self.config.restorefile)
            try:
                await asyncio.wait_for(self.finished.wait(), timeout=30)
            except asyncio.TimeoutError:
                pass
        logging.info("save_coro() finished")
    async def watchdog_coro(self):
        while not self.finished.is_set():
            start = time.time_ns()
            await asyncio.sleep(0.5)
            now = time.time_ns()
            seconds = (now-start) * 1e-9
            if seconds > 0.6:
                logging.warning(f"Watchdog task blocked for {seconds:0.2f} seconds")
    async def set_result(self, fqdn, nsec3):
        logging.debug(f"Result for {fqdn}: {nsec3}")
        #logging.debug(self.range_queue.keys())
        if nsec3.params != self.nsec3params:
            logging.error(f"Params have changed! before:{self.nsec3params} after:{nsec3.params}")
            self.finished.set()
            return
        h_from = NSEC3Hash.by_b32(nsec3.nsec3_from)
        h_to = NSEC3Hash.by_b32(nsec3.nsec3_to)
        logging.debug(f"{h_from} {h_to} {h_from < h_to}")
        self.dumperstatus.nrequests += 1
        if h_to < h_from:
            logging.warning(f"h_from < h_to (boundary reached): {h_from}, {h_to}")
            if not self.dumperstatus.is_solved(0, h_to.qint):
                self.dumperstatus.add_nsec(0, h_to.qint)
            if not self.dumperstatus.is_solved(h_from.qint, self.dumperstatus.maxvalue):
                self.dumperstatus.add_nsec(h_from.qint, self.dumperstatus.maxvalue)
        elif h_to == h_from:
            logging.warning(f"h_from == h_to, probably empty zone {h_from}, {h_to}")
            if not self.dumperstatus.is_solved(0, h_from.qint):
                self.dumperstatus.add_nsec(0, h_from.qint)
            if not self.dumperstatus.is_solved(h_to.qint, self.dumperstatus.maxvalue):
                self.dumperstatus.add_nsec(h_to.qint, self.dumperstatus.maxvalue)
        else:
            if self.dumperstatus.is_solved(h_from.qint, h_to.qint):
                logging.warning(f"Already solved: {h_from} {h_to}")
            else:
                #self.dumperstatus.print()
                self.dumperstatus.add_nsec(h_from.qint, h_to.qint)
                self.memcache.evict_entry(h_from.qint, h_to.qint)
                self.add_result(h_from)
                logging.info("Solve: " + h_from.b32())
                self.add_result(h_to)
                logging.info("Solve: "+ h_to.b32())
                self.last_hash=h_to.b32()

def main():
    parser=argparse.ArgumentParser(prog="dumper", description="Dump an NSEC3 zone")
    parser.add_argument('-v', '--verbose', action='count')
    parser.add_argument('-c', '--restore', action='store_true')
    parser.add_argument('-m', '--max-complexity', action='store')
    parser.add_argument('tld')
    args=parser.parse_args()
    verbose = defaultdict(lambda : logging.DEBUG, {None:logging.WARNING, 1:logging.INFO, 2:logging.DEBUG})
    logging.basicConfig(level=verbose[args.verbose])
    manager = DumpManager(config, args)
    manager.scan()

if __name__ == "__main__":
    main()
