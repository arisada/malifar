#!/usr/bin/env python3

# MIT License
# see LICENSE for more information
# Copyright (c) 2024 Aris Adamantiadis

import unittest
import os
import asyncio
import struct

from nsec3hash import prehash, antihash, hash_raw, NSEC3Hash, NSEC3Params, HashFinder
from cache import HAPCache, HAPFastNSEC3Cache, HAPNSEC3Cache, HAPException, HAPNotFoundException
from fastdns import DomainNoError, query_dnssec_async, connect_dns
from dumper import RangeList, DumperStatus

class TestNSEC3Hash(unittest.TestCase):
    hash_pairs = (
        ("xyz.com", b"\x03xyz\x03com\x00"),
        ("abcd.xyz.com", b"\x04abcd\x03xyz\x03com\x00"),
        ("ABCD.xyz.Com", b"\x04abcd\x03xyz\x03com\x00"),
        ("abcd.xyz.com.", b"\x04abcd\x03xyz\x03com\x00"),
        (".com", b"\x03com\x00")
    )

    anti_hash_pairs = (
        ("xyz.com", b"\x03xyz\x03com\x00"),
        ("abcd.xyz.com", b"\x04abcd\x03xyz\x03com\x00"),
        ("com", b"\x03com\x00")
    )
    def test_prehash(self):
        for h1, h2 in self.hash_pairs:
            self.assertEqual(h2, prehash(h1))

    def test_antihash(self):
        for h1, h2 in self.anti_hash_pairs:
            self.assertEqual(h1, antihash(h2))

class TestHAPCache(unittest.TestCase):
    filename="unittest_.hap"
    def setUp(self):
        try:
            os.unlink(self.filename)
        except FileNotFoundError:
            pass
    def tearDown(self):
        try:
            os.unlink(self.filename)
        except FileNotFoundError:
            pass

    def test_smoketest(self):
        cache = HAPCache()
        cache.htype=cache.HASH_FAST_NSEC3
        cache.set_loglevel("none")
        with self.assertRaises(HAPException):
            cache.load(self.filename)

    def test_create(self):
        cache = HAPCache()
        cache.htype=cache.HASH_FAST_NSEC3
        cache.create(self.filename)
    
    def test_open_empty(self):
        cache = HAPCache()
        cache.htype=cache.HASH_FAST_NSEC3
        cache.create(self.filename)
        del cache
        cache = HAPCache()
        cache.load(self.filename)
        self.assertEqual(cache.get_key_len(), 8)
        self.assertEqual(cache.get_value_len(), 16)
        self.assertEqual(cache.htype, cache.HASH_FAST_NSEC3)

    def test_set_metadata(self):
        md="This is the content I want"
        cache = HAPCache()
        cache.htype=cache.HASH_FAST_NSEC3
        cache.create(self.filename)
        cache.set_metadata(md)
        del cache
        cache = HAPCache()
        cache.load(self.filename)
        md2=cache.get_metadata()
        self.assertEqual(md, md2)

    def test_addentry(self):
        key=b"ABCDEFGH"
        value="abcd.efgh.com"
        cache = HAPCache()
        cache.htype=cache.HASH_FAST_NSEC3
        cache.set_loglevel("none")        
        cache.create(self.filename, value_len=14)
        cache.add_entry(key, value)
        cache.add_entry(key, value)
        cache.add_entry(key, value)
        del cache
        cache = HAPCache()
        cache.load(self.filename)
        cache.sort()
        cache.dump()
    def test_getentry_count(self):
        key=b"ABCDEFGH"
        value="abcd.efgh.com"
        cache = HAPCache()
        cache.htype=cache.HASH_FAST_NSEC3
        cache.set_loglevel("none")        
        cache.create(self.filename, value_len=14)
        self.assertEqual(cache.get_entries_count(), 0)
        cache.add_entry(key, value)
        self.assertEqual(cache.get_entries_count(), 1)
        cache.add_entry(key, value)
        self.assertEqual(cache.get_entries_count(), 2)
        cache.add_entry(key, value)
        self.assertEqual(cache.get_entries_count(), 3)
        
    def test_getentry(self):
        key=b"ABCDEFGH"
        value="abcd.efgh.icon"
        cache = HAPCache()
        cache.htype=cache.HASH_FAST_NSEC3
        cache.set_loglevel("none")
        cache.create(self.filename, value_len=14)
        cache.add_entry(key, value)
        cache.sort()
        k,v = cache.get_entry(0)
        self.assertEqual(key, k)
        self.assertEqual(bytes(value, "ascii"), v)

    def test_findentry(self):
        kv=(
            (b"ABCDEFGH","abcd.efgh.icon"),
            (b"XBCDEFGH","abcd.efgh.icon"),
            (b"ABCDEFGG","abcd.efgh.icon"),
            (b"ZZCDEFGH","abcd.efgh.icon"),
        )
        cache = HAPCache()
        cache.htype=cache.HASH_FAST_NSEC3
        cache.set_loglevel("none")
        cache.create(self.filename, value_len=14)
        for k,v in kv:
            cache.add_entry(k, v)
        cache.sort()
        self.assertEqual(cache.find_entry(kv[0][0]), 1)
        self.assertEqual(cache.find_entry(kv[1][0]), 2)
        self.assertEqual(cache.find_entry(kv[2][0]), 0)
        self.assertEqual(cache.find_entry(kv[3][0]), 3)
    def test_loglevel(self):
        cache=HAPCache()
        cache.set_loglevel("debug")
        cache.set_loglevel(4)
    def test_find_previous(self):
        cache = HAPCache()
        cache.htype=cache.HASH_FAST_NSEC3
        cache.create(self.filename, value_len=14)
        cache.set_loglevel("none")
        for i in range(100):
            k=bytes([i]) + b'A'*7
            v="A"*14
            cache.add_entry(k, v)
        cache.sort()
        for i in range(100):
            off = cache.find_previous_entry(bytes([i]) + b'1234567')
            self.assertEqual(off, i)
        self.assertEqual(cache.find_previous_entry(bytes(8)), 0)

class TestFastNSEC3Cache(unittest.TestCase):
    filename="unittest_.hap"
    def setUp(self):
        try:
            os.unlink(self.filename)
        except FileNotFoundError:
            pass
    def tearDown(self):
        try:
            os.unlink(self.filename)
        except FileNotFoundError:
            pass
    def test_addentry_int(self):
        key=0x4100
        value="abcd.efgh.com"
        cache = HAPFastNSEC3Cache()
        cache.set_loglevel("none")
        cache.create(self.filename, value_len=14)
        cache.add_entry_int(key, value)
        cache.sort()
        k,v = cache.get_entry(0)
        self.assertEqual(k, key)
        #self.assertEqual(v.strip(b'\x00'), bytes(value, "ascii"))
        self.assertEqual(v, value)

    def test_getentry_int(self):
        key = 0x1234
        value="abcd.efgh.com"
        cache = HAPFastNSEC3Cache()
        cache.set_loglevel("none")
        cache.create(self.filename, value_len=14)
        k_bytes = struct.pack(">Q", key)
        cache.add_entry(k_bytes, value)
        cache.sort()
        k,v = cache.get_entry_int(0)
        self.assertEqual(key, k)
        self.assertEqual(value, v)

    def test_has_between(self):
        cache = HAPFastNSEC3Cache()
        cache.create(self.filename, value_len=14)
        cache.set_loglevel("none")
        for i in range(0x0, 0x65):
            k=bytes([0] * 6 + [i] + [0])
            v="A"*14
            cache.add_entry(k, v)
        cache.sort()
        self.assertTrue(cache.has_between(0x0, 0x1000))
        #cache.set_loglevel("debug")
        self.assertTrue(cache.has_between(0x5000, 0x6000))
        self.assertTrue(cache.has_between(0x4f00, 0x6000))
        self.assertFalse(cache.has_between(0x4f01, 0x4fff))
        self.assertTrue(cache.has_between(0x4f01, 0x5001))

    def test_has_between(self):
        cache = HAPFastNSEC3Cache()
        cache.create(self.filename, value_len=14)
        cache.set_loglevel("none")
        for i in range(0x0, 0x65):
            k=bytes([0] * 6 + [i] + [0])
            v="A"*14
            cache.add_entry(k, v)
        cache.sort()
        entry = cache.get_between(0x5000, 0x6000)
        self.assertEqual(cache.get_entry(entry), 
            (0x5100, "A"*14))
    
    def test_find_empty(self):
        cache = HAPFastNSEC3Cache()
        cache.create(self.filename, value_len=14)
        self.assertFalse(cache.has_between(0x0, 0x1000))

    def test_dedup(self):
        cache = HAPFastNSEC3Cache()
        cache.create(self.filename, value_len=14)
        value="A"*14
        keys = [5, 5, 7, 3, 5, 1, 1, 4, 3]
        sorted_keys = [1, 3, 4, 5, 7]
        for k in keys:
            cache.add_entry_int(k, value)
        cache.dedup()
        #for i in range(9):
        #    k, v = cache.get_entry(i)
        #    print(k, v)
        self.assertEqual(cache.get_entries_count(), len(sorted_keys))
        for i, k in zip(range(len(sorted_keys)), sorted_keys):
            self.assertEqual(k, cache.get_entry(i)[0])



class TestNSEC3Cache(unittest.TestCase):
    filename="unittest_.hap"
    h = NSEC3Hash(b'A'*20)
    def setUp(self):
        try:
            os.unlink(self.filename)
        except FileNotFoundError:
            pass
    def tearDown(self):
        try:
            os.unlink(self.filename)
        except FileNotFoundError:
            pass
    def test_addentry(self):
        cache = HAPNSEC3Cache()
        cache.set_loglevel("none")
        cache.create(self.filename)
        cache.add_entry(self.h)
        cache.sort()
        k = cache.get_entry(0)
        self.assertEqual(k, self.h)

class TestAsyncDNS(unittest.IsolatedAsyncioTestCase):
    async def testConnectDNS(self):
        s = await connect_dns("127.0.0.1")
        await s.close()
        await s.writer.wait_closed()

    async def testGetNSEC3(self):
        s = await connect_dns("127.0.0.1")
        ns3 = await query_dnssec_async(s, "li", "dqfsfqdfqsdfqsdf.li")
        await s.close()
        await s.writer.wait_closed()
        self.assertEqual(ns3.params, NSEC3Params(domain='li', flags=1, iterations=0, salt=b''))
        self.assertEqual(ns3.nsec3_from, "7n793u8er8ash4dnjsi2cfn5p8p8g5m3")
        self.assertEqual(ns3.nsec3_to, "7nae2ecfvetgoiooa8g4dvr0tclblqj9")

    async def testGetNSEC3_loop(self):
        s = await connect_dns("127.0.0.1")
        for i in range(10):
            ns3 = await query_dnssec_async(s, "li", "dqfsfqdfqsdfqsdf.li")
            self.assertEqual(ns3.params, NSEC3Params(domain='li', flags=1, iterations=0, salt=b''))
            self.assertEqual(ns3.nsec3_from, "7n793u8er8ash4dnjsi2cfn5p8p8g5m3")
            self.assertEqual(ns3.nsec3_to, "7nae2ecfvetgoiooa8g4dvr0tclblqj9")
        await s.close()
        await s.writer.wait_closed()

class TestRange(unittest.TestCase):
    def setUp(self):
        self.ranges=RangeList()
        self.ranges.add(1,3)
        self.ranges.add(7,9)
        self.ranges.add(10,14)

    def testIsInRange(self):
        for i in [1, 2, 3, 7, 8, 9, 10, 11, 12, 13, 14]:
            self.assertTrue(self.ranges.is_in_range(i))
        for i in [4, 5, 6, 15, 16]:
            self.assertFalse(self.ranges.is_in_range(i))
    def testGetRangeIndex(self):
        values = [
            (1, 0), (2, 0), (3, 0),
            (7, 1), (8, 1), (9, 1),
            (10, 2), (11, 2), (14, 2),
        ]
        for i, j in values:
            self.assertEqual(self.ranges.get_range_index(i), j)        
    def testPopIfExist(self):
        self.assertEqual(self.ranges.pop_if_exist(5), None)
        self.assertEqual(self.ranges.pop_if_exist(8), (7, 9))
        self.assertFalse(self.ranges.is_in_range(8))
    def testZeroRange(self):
        self.ranges=RangeList()
        self.ranges.add(0, DumperStatus.maxvalue)
        self.assertTrue(self.ranges.is_in_range(0))
        for i in [1, 5, 10]:
            self.assertTrue(self.ranges.is_in_range(i))
#        self.assertFalse(self.ranges.is_in_range(1001))

    def testCoalesce1(self):
        self.ranges.add(3, 7)
        self.ranges.coalesce(3,7)
        self.assertEqual(list(self.ranges), [(1,9), (10,14)])
        self.ranges.add(9, 10)
        self.ranges.coalesce(9, 10)
        self.assertEqual(list(self.ranges), [(1,14)])

    def testCoalesce2(self):
        self.ranges.add(9, 10)
        self.ranges.coalesce(9, 10)
        self.assertEqual(list(self.ranges), [(1,3), (7,14)])

    def testOverlap1(self):
        self.ranges.add(8, 10)
        self.ranges.coalesce(8, 10)
        self.assertEqual(list(self.ranges), [(1,3), (7,14)])
        self.ranges.add(2, 4)
        self.ranges.coalesce(2, 4)
        self.assertEqual(list(self.ranges), [(1,4), (7,14)])
    def testOverlap2(self):
        for i in range(15, 30, 3):
            self.ranges.add(i, i+2)
        self.ranges.add(14, 31)
        self.ranges.coalesce(14, 31)
        #print(list(self.ranges))
        self.assertEqual(list(self.ranges), [(1,3), (7,9), (10, 31)])

    def testOverlap2(self):
        self.ranges.add(6, 15)
        #print(list(self.ranges))
        self.assertEqual(list(self.ranges), [(1,3), (6,15)])

    def testRemove1(self):
        self.ranges.remove(7,9)
        self.assertEqual(list(self.ranges), [(1,3), (10, 14)])
        self.ranges.remove(1,3)
        self.assertEqual(list(self.ranges), [(10, 14)])

        self.ranges.remove(9, 15)
        self.assertEqual(list(self.ranges), [])

    def testRemove2(self):
        self.ranges.remove(0, 15)
        self.assertEqual(list(self.ranges), [])
    def testRemove3(self):
        self.ranges.remove(2, 3)
        self.assertEqual(list(self.ranges), [(1,2), (7,9), (10, 14)])

        self.ranges.remove(5, 8)
        self.assertEqual(list(self.ranges), [(1,2), (8,9), (10, 14)])

        self.ranges.remove(11, 13)
        self.assertEqual(list(self.ranges), [(1,2), (8,9), (10, 11), (13, 14)])


class TestDumperStatus(unittest.TestCase):
    def setUp(self):
        self.dumper = DumperStatus()
        self.dumper.add_nsec(0, 1000)
        self.dumper.add_nsec(5000, DumperStatus.maxvalue)
        self.dumper.check_consistency()

    def tearDown(self):
        try:
            os.unlink("test.restore")
        except FileNotFoundError:
            pass

    def testInitial_conditions(self):
        self.assertTrue(self.dumper.solved.is_in_range(0))
        self.assertTrue(self.dumper.solved.is_in_range(1000))
        self.assertTrue(self.dumper.solved.is_in_range(5000))
        self.assertTrue(self.dumper.solved.is_in_range(DumperStatus.maxvalue))
        self.assertFalse(self.dumper.solved.is_in_range(1001))
        self.assertFalse(self.dumper.solved.is_in_range(4999))

        self.assertFalse(self.dumper.holes.is_in_range(0))
        self.assertFalse(self.dumper.holes.is_in_range(999))
        self.assertTrue(self.dumper.holes.is_in_range(1000))
        self.assertTrue(self.dumper.holes.is_in_range(1001))
        self.assertTrue(self.dumper.holes.is_in_range(4999))
        self.assertTrue(self.dumper.holes.is_in_range(5000))
        self.assertFalse(self.dumper.holes.is_in_range(5001))
        self.assertFalse(self.dumper.holes.is_in_range(DumperStatus.maxvalue))
        self.dumper.check_consistency()

    def testCase0(self):
        self.dumper.add_nsec(1000, 5000)
        self.assertEqual(len(self.dumper.holes), 0)
        self.assertEqual(len(self.dumper.solved), 1)
        self.assertTrue(self.dumper.solved.is_in_range(2000))
        self.assertFalse(self.dumper.holes.is_in_range(2000))
        self.dumper.check_consistency()
        #self.dumper.print()
    def testCase0_2(self):
        self.dumper.add_nsec(2000, 3000)
        self.assertEqual(len(self.dumper.holes), 2)
        self.assertEqual(len(self.dumper.solved), 3)
        self.assertTrue(self.dumper.solved.is_in_range(2500))
        self.assertFalse(self.dumper.holes.is_in_range(2500))
        #self.dumper.print()
        # What happens if we hit that solve twice ?
        self.dumper.add_nsec(2000, 3000)
        self.dumper.add_nsec(2001, 2999)
        self.dumper.check_consistency()
        #self.assertEqual(len(self.dumper.holes), 2)
        #self.assertEqual(len(self.dumper.solved), 3)
        #self.assertTrue(self.dumper.solved.is_in_range(2500))
        #self.assertFalse(self.dumper.holes.is_in_range(2500))


    def testCase1(self):
        self.dumper.add_nsec(1000, 2001)
        self.assertEqual(len(self.dumper.holes), 1)
        self.assertEqual(len(self.dumper.solved), 2)
        self.assertTrue(self.dumper.solved.is_in_range(2000))
        self.assertFalse(self.dumper.holes.is_in_range(2000))
        self.dumper.check_consistency()

    def testCase2(self):
        self.dumper.add_nsec(2000, 3000)
        self.assertEqual(len(self.dumper.holes), 2)
        self.assertEqual(len(self.dumper.solved), 3)
        self.assertTrue(self.dumper.solved.is_in_range(2500))
        self.assertFalse(self.dumper.holes.is_in_range(2500))
        self.assertFalse(self.dumper.solved.is_in_range(1500))
        self.assertTrue(self.dumper.holes.is_in_range(1500))
        self.assertFalse(self.dumper.solved.is_in_range(4000))
        self.assertTrue(self.dumper.holes.is_in_range(4000))
        self.dumper.check_consistency()

    def testCase3(self):
        self.dumper.add_nsec(3000, 5000)
        self.assertEqual(len(self.dumper.holes), 1)
        self.assertEqual(len(self.dumper.solved), 2)
        self.assertTrue(self.dumper.solved.is_in_range(4000))
        self.assertFalse(self.dumper.holes.is_in_range(4000))
        self.dumper.check_consistency()
        #self.dumper.print()

    def testEq(self):
        dumper = DumperStatus()
        dumper.add_nsec(0, 1000)
        dumper.add_nsec(5000, DumperStatus.maxvalue)
        self.assertEqual(self.dumper, dumper)

    def testSave(self):
        self.dumper.save("test.restore")
        with open("test.restore", "r") as f:
            file = f.read()
        expected=f"holes\n1000 5000\nsolved\n0 1000\n5000 {self.dumper.maxvalue}\nnrequests\n0\n"
        self.assertEqual(file, expected)

    def testLoad(self):
        self.dumper.save("test.restore")
        dumper2 = DumperStatus()
        dumper2.load("test.restore")
        self.assertEqual(self.dumper, dumper2)

    def testRealcase(self):
        dumper=DumperStatus()
        dumper.add_nsec(0, 3042901074927301135)
        dumper.add_nsec(3042908773552737583,3042910343120770244)
        dumper.add_nsec(3042912554086624018, 3042923225197087791)
        dumper.add_nsec(3042930497970604540, 3042940242781601074)

        """Solv(3042908773552737583,3042910343120770244) here
        Hole(3042910343120770244,3042912554086624018)
        Solv(3042912554086624018,3042923225197087791) <- this entry disappeared
        Hole(3042923225197087791, 3042930497970604540) to here"""
        
        dumper.check_consistency()
        dumper.add_nsec(3042910343120770244, 3042923225197087791)
        dumper.check_consistency()
    def testSimpleRealCase1(self):
        # 0-1000 5000-end
        self.dumper.add_nsec(3000, 4000)
        # overwrite the 3000-4000 range
        self.dumper.add_nsec(2000, 4000)
        # 0-1000 2000-4000 5000-end
        holes = list(self.dumper.holes)
        self.assertEqual(holes, [(1000, 2000), (4000, 5000)])
        solved = list(self.dumper.solved)
        #print(solved)
        self.assertEqual(solved, [(0, 1000), (2000, 4000), 
            (5000, self.dumper.maxvalue)])

    def testSimpleRealCase2(self):
        # 0-1000 5000-end
        self.dumper.add_nsec(3000, 4000)
        # overwrite the 3000-4000 range
        self.dumper.add_nsec(1000, 4000)
        # 0-4000 5000-end
        holes = list(self.dumper.holes)
        self.assertEqual(holes, [(4000, 5000)])
        solved = list(self.dumper.solved)
        #print(solved)
        self.assertEqual(solved, [(0, 4000), 
            (5000, self.dumper.maxvalue)])

class TestHashFinder(unittest.TestCase):
    class pbar():
        def update(_):
            pass
        def set_description(_):
            pass

    def prepare(self, params):
        self.solver = HashFinder(tld=params.domain, salt=params.salt, 
            iterations=params.iterations, nthreads=2**16, max_nholes=100)
        self.solver.prepare()
        self.holes = [(0, 0xffffffffff)]
        self.solved = self.solver.match_hashes(self.holes, pbar=self.pbar)

    def checkHash(self, params):
        self.prepare(params)
        s = self.solved[0]
        h = NSEC3Hash.hash(s[2], params)
        self.assertTrue(h.qint >= s[0] and h.qint <= s[1])

    def testHashSimple(self):
        nsec3params=NSEC3Params(domain="com", salt=b"", iterations=0)
        self.checkHash(nsec3params)

    def testHashIterations1(self):
        nsec3params=NSEC3Params(domain="com", salt=b"", iterations=1)
        self.checkHash(nsec3params)

    def testHashIterations10(self):
        nsec3params=NSEC3Params(domain="com", salt=b"", iterations=10)
        self.checkHash(nsec3params)

    def testHashSalt(self):
        nsec3params=NSEC3Params(domain="com", salt=b"4141", iterations=0)
        self.checkHash(nsec3params)

    def testHash3IterationsSalt(self):
        nsec3params=NSEC3Params.from_serial("com 1 1 10 4141")
        self.checkHash(nsec3params)

    def testHash8IterationsSalt(self):
        nsec3params=NSEC3Params.from_serial("comxxxxx 1 1 10 4141")
        self.checkHash(nsec3params)

if __name__ == '__main__':
    unittest.main()
