#!/usr/bin/env python3

# MIT License
# see LICENSE for more information
# Copyright (c) 2024 Aris Adamantiadis

import sys
import asyncio
import time
from fastdns import query_dnssec_async, connect_dns, dns_query

async def probe_ns(fqdn, ip):
    s=await(connect_dns(ip))
    try:
        for i in range(0, 200):
            rc = await query_dnssec_async(s, tld=fqdn, fqdn=fqdn)
        print(f"No exception, {ip} is probably unlimited")
    except (EOFError, ConnectionResetError):
        pass
    maxreqs = i
    try:
        await s.close()
        await s.writer.wait_closed()
    except ConnectionResetError:
        pass
    
    s=await(connect_dns(ip))
    start=time.time_ns()
    try:
        for i in range(0, 200):
            rc = await query_dnssec_async(s, tld=fqdn, fqdn=fqdn)
            await asyncio.sleep(0.3)
        print(f"No exception, {ip} has probably no timeout")
    except (EOFError, ConnectionResetError):
        pass
    end=time.time_ns()
    seconds = (end-start)*1e-9
    print(f"ns {ip} maxreqs {maxreqs} timeout {seconds:0.2f}")
    try:
        await s.close()
        await s.writer.wait_closed()
    except ConnectionResetError:
        pass

async def probe_nameservers(tld, ips):
    fqdn = "fqozijoqijfqezr." + tld
    coros= [probe_ns(fqdn, ip) for ip in ips]
    await asyncio.gather(*coros)

def main():
    tld = sys.argv[1]
    print(f"Querying tld {tld}")
    ns = dns_query(tld, "NS")
    ns_ips=[]
    for n in ns:
        ns_ips += dns_query(n, "A")
        ns_ips += dns_query(n, "AAAA")
    ns_ips.sort()
    print("Nameservers: ", ns_ips)
    asyncio.run(probe_nameservers(tld, ns_ips))

if __name__ == "__main__":
    main()
