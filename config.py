# configuration file for the nsec3 scanner

baseconfig = {
    "cachefile": "{workdir}/{tld}.cache",
    "zonefile": "{workdir}/{tld}-{date}.zone",
    "crackservice": "127.0.0.1:4000",
    "workdir": "workdir",
    "restorefile": "{workdir}/{tld}.restore",
    "maxreqs": 1000,
    "timeout": 90,
    "maxcomplexity":39,
    "concurrency": 1,
    "domains": [
        { "name":"example", "maxreqs": 20, "concurrency": 2, "timeout": 5}
    ]
}

try:
    from config_local import config
    for k in baseconfig.keys():
        if not k in config.keys():
            config[k]=baseconfig[k]
except ModuleNotFoundError:
    print("Loading base configuration. You probably want to finetune it.")
    config = baseconfig
