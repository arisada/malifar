# Malifar GPU-accelerated NSEC3 Zone Walker
## Disclaimer

This tool may generate a large amount of DNS traffic to critical infrastructure. While the default
settings are believed to be safe, be sure you understand the consequences of launching large scans
before your run this tool on large DNS zones.

## How it works

Malifar works by exploiting the NSEC3 zone walking weakness. It's splitting the work
between two processes: the main dumper (`dumper.py`) and a GPU-accelerated `crackserver.py`.
The dumper generates requests to splice the unexplored areas in the hashed nsec3
space. Unexplored areas are sent to the crackserver process and fqdn candidates are sent back.
In most cases this is very fast, but sometimes tough holes are found that may require between
10 minutes and a few hours of cracking. By default, no job more difficult than 2^39 will be sent
to the crack server but this can be configured in `config_local.py` or `-m` command line option.


```sh
./dumper.py domain
```

The dumper generates three files:
* `domain-DATE.zone`: this file contains the zone information that was extracted from the zone.
* `domain.cache`: a cache file containing all intermediate hashes that were useful to the domain
extraction. This file will be reused later so less GPU cracking is required.
* `domain.restore`: a very simple snapshot of the scanner's state so a scan can be recovered later.

The files may be extracted in a way that can be parsed by hashcat with

```sh
./haptool.py -f workdir/domain-date.zone hashcat -o out.hashcat
```

## How does it differ from nsec3map

nsec3map works really well but requires a lot of memory and CPU on larger zones. Malifar has a few
notable differences:

* GPU acceleration: searching for intermediate hashes is accelerated with OpenCL. x1000 performance boost
* asyncio design: more modern Python and better handling of IOs
* DNS over TCP instead of UDP
* GPU cracking and network parts can be on different computers
* Optimized cache and result files
* Optimized RAM usage. Malifar dumps a 10M records zone with less than 1G RAM on a single core.
* Per-domain configuration parameters in case we repeat scans regularly.

Malifar currently does not support NSEC and does not implement any attack against anti-scanning countermeasures.

## Installation

You need Swig 4, CMake, libssl-dev.
```sh
mkdir hap/build
cd hap/build
cmake ..
make
cd ../..
pip3 install -r requirements.txt
```

Malifar has been tested on Ubuntu 22.04 with nvidia RTX cards and osx on M2. Other
platforms may require tweaking the OpenCL code.

## Publications

Malifar will be presented at SSTIC2024 https://www.sstic.org/2024/presentation/dig_com_axfr_dnssec__lister_linternet_grce__dnssec/
