# acn-py
Autoconfiguration and installation of a apt-cacher-ng server and configuration of cron-apt to download automatically the updates and install the security updates.

## Dowload the dir acn-py

## Build the deb packge

```
$ dpkg --build acn-py/
# dpkg -i acn-py.deb
```

## Requires
python3
python3-nmap

## Specific files install
/etc/apt/apt.conf.d/00aptproxyANC 
/etc/apt/sources.list.d/security-primtuxACN.list 
/etc/cron-apt/action.d/5-primtuxACN-security




