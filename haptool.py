#!/usr/bin/env python3

# MIT License
# see LICENSE for more information
# Copyright (c) 2024 Aris Adamantiadis

import argparse
import codecs
import os
from cache import HAPCache, HAPFastNSEC3Cache, HAPNSEC3Cache
from nsec3hash import NSEC3Params, NSEC3Hash
from tqdm import trange

def dump(args):
    cache = HAPCache()
    cache.load(args.file)
    print("hash type:", cache.htype)
    if cache.htype == cache.HASH_FAST_NSEC3:
        cache=HAPFastNSEC3Cache()
    elif cache.htype == cache.HASH_NSEC3:
        cache=HAPNSEC3Cache()
    else:
        raise Exception(f"Unknown hash type {cache.htype}")
    cache.load(args.file)
    nentries = cache.get_entries_count()
    if args.limit:
        n = int(args.limit)
    else:
        n = nentries
    for i in range(n):
        entry = cache.get_entry(i)
        if isinstance(entry, tuple):
            key, value = entry
            print(key, value)
        else:
            print(entry)

def info(args):
    cache = HAPCache()
    cache.load(args.file)
    print("hash type:", cache.htype)
    print("metadata:", cache.get_metadata())
    print("key len, data len:", cache.get_key_len(), cache.get_value_len())
    print("Number of records:", cache.get_entries_count())
    #print(cache)

def dedup(args):
    cache = HAPCache()
    cache.load(args.file)
    x,y = cache.dedup()
    print("Cache space saved:", x, y, y * 100 / x)

def hashcat(args):
    if args.output == None:
        print("Output (--output) file needed")
        return
    cache = HAPNSEC3Cache()
    cache.load(args.file)
    with open(args.output, "w") as output:
        try:
            params = NSEC3Params.from_serial(cache.get_metadata())
        except ValueError as e:
            print("Invalid nsec3 params in metadata:", cache.get_metadata())
            raise e
        print("Using params:", params)
        # should look like u27tlijle7l2k79t729694u6p7n0eufe:.com:41424344:0
        params_txt = f":.{params.domain}:{params.salt.hex()}:{params.iterations}\n"
        for i in trange(cache.get_entries_count()):
            h = cache.get_entry(i)
            #h = NSEC3Hash(codecs.decode(k, "hex"))
            output.write(h.b32() + params_txt)

def set_metadata(args):
    if args.parameter == None:
        print("Metadata (--parameter) needed")
        return
    cache = HAPCache()
    cache.load(args.file)
    print("metadata:", cache.get_metadata())
    cache.set_metadata(args.parameter)

def prune(args):
    cache = HAPCache()
    cache.load(args.file)
    print("Number of records:", cache.get_entries_count())
    if cache.get_entries_count() < 100:
        print(f"Unlinking file {args.file}")
        os.unlink(args.file)

def main():
    parser = argparse.ArgumentParser(prog='haptool')
    parser.add_argument('-f', '--file', help="file to operate on", required=True)
    parser.add_argument('-l', '--limit', help="limit to n first results")
    parser.add_argument('-o', '--output', help="output file (hashcat)")
    parser.add_argument('-p', '--parameter', help="parameter to the command (set-metadata)")
    parser.add_argument('command')
    #subparsers = parser.add_subparsers(help='sub-command help')
    #parser_dump = subparsers.add_parser('dump', help='a help')
    args = parser.parse_args()
    if args.command == 'info':
        info(args)
    elif args.command == 'dump':
        dump(args)
    elif args.command == 'dedup':
        dedup(args)
    elif args.command == 'hashcat':
        hashcat(args)
    elif args.command == 'set-metadata':
        set_metadata(args)
    elif args.command == 'prune':
        prune(args)
    else:
        print(f"Unknown command {args.command}")
        print("commands: info dump dedup hashcat set-metadata prune")
        return
if __name__=="__main__":
    main()
