# netre
Net read - a project that scan you server and resume you all vulnerability and how to patch them

## netre.py

This Python script summarizes network information on a Linux system. It prints the system's IP addresses, open ports and running services using standard command-line tools (`ip`, `ss`, `systemctl`).

It can also scan the local host for known vulnerabilities using `nmap`'s
`vulners` script. The vulnerability scan relies on the `nmap` command line tool
and the `python-nmap` library.

Run it with:

```bash
python3 netre.py
```

### Requirements

Install the following packages on Ubuntu/Debian systems:

```bash
sudo apt-get install nmap python3-nmap
```

The scan will run even if these packages are missing, but the vulnerabilities
section will be empty.
