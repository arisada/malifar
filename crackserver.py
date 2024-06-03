#!/usr/bin/env python3

# MIT License
# see LICENSE for more information
# Copyright (c) 2024 Aris Adamantiadis

import asyncio
import traceback
import tqdm
import signal
from nsec3hash import HashFinder, hash_raw, NSEC3Params, NSEC3Hash

nthreads = 2**20
nholes = 2**16
class Finish():
    def __init__(self):
        self.finished=False

finish=Finish()

async def solve_holes(solver, params, reader, writer, pbar):
    print("New solving loop")
    blocklist = set()
    lines = [await reader.readline()]
    while True:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=0.05)
            if line:
                lines.append(line)
            else:
                raise Exception("Peer disconnected")
        except asyncio.TimeoutError:
            print("timeout")
            break;
    for line in lines:
        if line.startswith(b"bl"):
            bl = str(line, "ascii")
            bl = bl[3:].strip().split(',')
            blocklist=set(bl)
            lines.remove(line)
            break
    print("blocklist:", blocklist)
    holes=[i.split(b' ')[:2] for i in lines]
    holes=[(int(a),int(b)) for a,b in holes]
    print(holes[:16])
    if len(holes) > 16:
        print("...")
    holes.sort()
    # Run in an executor
    def matchhash():
        solved = solver.match_hashes(holes, pbar=pbar, finish=finish, bl=blocklist)
        return solved
    pbar.reset()
    solved = await asyncio.get_event_loop().run_in_executor(None, matchhash)
    #pbar.clear()
    if len(solved) != len(holes):
        raise Exception("Incomplete solution")
    print(len(holes), len(solved))
    for h, s in zip(holes, solved):
        assert(h[0] == s[0])
        if h[1] != s[1]:
            print("Assertion error:", h, s, "probably due to confusion in cracking state")
        assert(h[1] == s[1])
    for i in solved:
        h = NSEC3Hash.hash(i[2], params)
        print (hex(i[0]), hex(i[1]), i[2], h, hex(h.qint))
        if h.qint <= i[0] or h.qint >= i[1]:
            print("Probable error, check params!!")
        writer.write(bytes(f'{i[0]} {i[1]} {h.qint} {i[2]}\n', "ascii"))
    await writer.drain()

async def handle_solver(reader, writer):
    try:
        print("New client")
        params = await reader.readline()
        print("Params", params)
        params = str(params, "ascii").strip('\n')
        nsec3params = NSEC3Params.from_serial(params)
        print("nsec3params:", nsec3params)

        solver=HashFinder(tld=nsec3params.domain, salt=nsec3params.salt, 
            iterations=nsec3params.iterations, nthreads=nthreads, max_nholes=nholes)
        solver.prepare()
        print("Ready!")
        with tqdm.tqdm(dynamic_ncols=True) as pbar:
            while True:
                await solve_holes(solver, nsec3params, reader, writer, pbar)
    except Exception as e:
        print("Exception:", e)
        traceback.print_exc()

def inner_signal_handler(sig, frame):
    finish.finished=True
    signal.signal(signal.SIGINT, signal.SIG_DFL)

async def aio_main():
    print("Listening...")
    server = await asyncio.start_server(handle_solver, "0.0.0.0", 4000)
    async with server:
        await server.serve_forever()

if __name__=="__main__":
    signal.signal(signal.SIGINT, inner_signal_handler)
    asyncio.run(aio_main())    
