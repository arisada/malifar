#!/usr/bin/env python3

import socket
import asyncio
from collections import namedtuple
import logging
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import dns.resolver
import dns.asyncquery
import dns.asyncbackend
import time
import ipaddress

from nsec3hash import NSEC3Params, NSEC3Hash

aio_backend = dns.asyncbackend.get_backend("asyncio")

class DomainNoError(Exception):
    pass

class UnknownDNSError(Exception):
    pass

class UnexpectedNSECError(Exception):
    pass

NSEC3Response = namedtuple("NSEC3Response", ("params", "nsec3_from", "nsec3_to"))

async def query_dnssec_async(s, tld, fqdn):
    """Query a (non existing) domain with dnssec to get an NSEC
    or NSEC3 answer"""
    qname = dns.name.from_text(fqdn)
    q = dns.message.make_query(qname, dns.rdatatype.A, want_dnssec=True)
    #ip = nameserver
    r = await dns.asyncquery.tcp(q, where=None, sock=s, timeout=3, backend=asyncio)
    
    if r.rcode() == dns.rcode.NOERROR:
        raise DomainNoError(f"fqdn {fqdn} has A record")

    if r.rcode() != dns.rcode.NXDOMAIN:
        logging.error(f"Expected NXDOMAIN: {r.rcode()}")
        logging.error(str(r))
        raise UnknownDNSError(f"fqdn {fqdn} Unknown code {r.rcode()}")

    nsec3 = [i for i in r.authority if i.rdtype == dns.rdatatype.NSEC3]
    nsec = [i for i in r.authority if i.rdtype == dns.rdatatype.NSEC]
    #print("nsec3:", nsec3)
    #print("nsec:", nsec)
    if len(nsec) > 0:
        raise UnexpectedNSECError(f"fqdn {fqdn} NSEC reply")
    if len(nsec3) < 1:
        for i in nsec3:
            print(i)
        raise UnexpectedNSECError(f"fqdn {fqdn} expected 1-3 nsec3 (got {len(nsec3)})")
    
    fields = nsec3[0].to_text().split(" ")
    params = fields[3:8]
    ns3params = NSEC3Params(domain=tld, params=params[1:])
    h = NSEC3Hash.hash(fqdn, ns3params)
    for i in nsec3:
        fields = i.to_text().split(" ")
        params = fields[3:8]
        nsec3_from = fields[0].lower().split('.')[0]
        nsec3_to = fields[8].lower()
        h1 = NSEC3Hash.by_b32(nsec3_from)
        h2 = NSEC3Hash.by_b32(nsec3_to)
        if h1 < h2:
            if h1 < h and h < h2:
                return NSEC3Response(ns3params, nsec3_from, nsec3_to)
        else:
            if h1 < h or h < h2:
                return NSEC3Response(ns3params, nsec3_from, nsec3_to)
    logging.error("Couldn't find matching nsec3 record:", h.b32())
    logging.error(str(nsec3))

async def connect_dns(ip):
    if ipaddress.ip_address(ip).version == 4:
        af=socket.AF_INET
    else:
        af=socket.AF_INET6
    s = await aio_backend.make_socket(af=af, socktype=
                socket.SOCK_STREAM, proto=0, destination=(ip, 53), timeout=10)
    return s

async def full_query_dnssec(tld, fqdn, ns="8.8.8.8"):
    s = await connect_dns(ns)
    rc = await query_dnssec_async(s, tld, fqdn)
    await s.close()
    await s.writer.wait_closed()
    return rc

async def scanner_coroutine(ip, manager):
    maxreqs = manager.config.maxreqs
    maxtime = manager.config.timeout
    while True:
        try:
            if manager.finished.is_set():
                logging.info(f"Coro {ip} terminating")
                return
            logging.info(f"Connecting to {ip}")
            s = await connect_dns(ip)
            connected_ns = time.time_ns()
            requests = 0
            while True:
                try:
                    next_fqdn = await asyncio.wait_for(manager.next_fqdn(), timeout=0.1)
                    if next_fqdn == None:
                        logging.info(f"Coro {ip} terminating")
                        await s.close()
                        await s.writer.wait_closed()
                        return
                    else:
                        fqdn, h = next_fqdn
                except asyncio.TimeoutError:
                    #logging.warning(f"Queue timeout for {ip}, {requests}")
                    ms_connected = (time.time_ns() - connected_ns) * 1e-6
                    if ms_connected > (maxtime-0.2) * 1000:
                        logging.debug(f"Proactive disconnect {ip} {ms_connected} ms")
                        break
                    continue    
                ms_connected = (time.time_ns() - connected_ns) * 1e-6
                if ms_connected > (maxtime-0.2) * 1000:
                    logging.debug(f"Proactive disconnect {ip} {ms_connected} ms")
                    manager.remove_range(h)
                    break
                start=time.time_ns()
                try:
                    ns3 = await query_dnssec_async(s, manager.tld, fqdn)
                    start=time.time_ns()
                    requests += 1
                    await manager.set_result(fqdn, ns3)
                    #await asyncio.sleep(0.2)
                except UnexpectedNSECError as e:
                    logging.error(f"Coro {ip} error " + str(e))
                    manager.remove_range(h)
                    break
                except DomainNoError as e:
                    logging.error(f"Coro {ip} error " + str(e))
                    manager.remove_range(h)
                    manager.evict_cache(h, fqdn)
                    break
                except (EOFError, BrokenPipeError, ConnectionResetError):
                    ms = (time.time_ns() - start) * 1e-6
                    ms_connected = (time.time_ns() - connected_ns) * 1e-6
                    logging.error(f"Disconnected from {ip}, {requests} requests {ms} ms, connected {ms_connected} ms")
                    manager.remove_range(h)
                    break
                except dns.exception.Timeout as e:
                    logging.error(f"Timeout from {ip}, connected {ms_connected} ms: {e}")
                    manager.remove_range(h)
                    break
                manager.remove_range(h)
                if maxreqs and requests >= maxreqs:
                    break
            try:
                await s.close()
                await s.writer.wait_closed()
            except:
                pass
            logging.info(f"connection to {ip} closed")
        except ConnectionRefusedError:
            logging.error(f"{ip}: Connection Refused")
            await asyncio.sleep(10)
        except dns.exception.Timeout as e:
            logging.error(f"Timeout connecting to {ip} ms: {e}")
            await asyncio.sleep(10)

def dns_query(fqdn, dtype_s, resolver="8.8.8.8"):
    """Make a recursive call to list authoritative servers (NS)
    for the fqdn"""
    qname = dns.name.from_text(fqdn)
    dtype = {
        "NS": dns.rdatatype.NS,
        "A": dns.rdatatype.A,
        "AAAA": dns.rdatatype.AAAA
    }[dtype_s]
    q = dns.message.make_query(qname, dtype)
    r = dns.query.tcp(q, resolver)
    #if dtype_s=='A':
    #    print(r)
    #print("answer")
    records = [i for i in r.answer if i.rdtype == dtype]
    if len(records) < 1:
        print("Empty answer")
        return []
    if len(records) > 1:
        print("too large")
        print(records)
        return None
    record=records[0]
    ret = [str(i) for i in record]
    ret.sort()
    #print(NS)
    return ret

ip="127.0.0.1"


async def my_client():
    s = await connect_dns(ip)
    ns3 = await query_dnssec_async(s, "li", "dqfsfqdfqsdfqsdf.li")
    print(ns3)
    await s.close()
    await s.writer.wait_closed()

def aio_main():
    asyncio.run(my_client())
    #loop = asyncio.get_event_loop()
    #result = loop.run_until_complete(my_client())
    #loop.close()
    #print("Finished", result)

def main():
    aio_main()
    return
    s=socket.socket()
    s.connect((ip, 53))
    query_nxdomain_dnssec(s, "com")
    query_nxdomain_dnssec(s, "com")
    query_nxdomain_dnssec(s, "com")

if __name__=="__main__":
    main()
