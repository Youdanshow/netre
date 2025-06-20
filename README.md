# netre (ip, ss, systemctl, ipconfig, netstat, ifconfig, lsof, sc, nmap)
Net read - a project that scan you server and resume you all vulnerability and how to patch them

## netre.py (uses `ip`, `ss`, `systemctl`, `ipconfig`, `netstat`, `ifconfig`, `lsof`, `sc`, `nmap`)

This Python script summarizes network information on the host system. On Linux it relies on `ip`, `ss` and `systemctl`. On Windows it uses `ipconfig` and `netstat`, while macOS support falls back to `ifconfig` and `lsof`.

It can also scan the local host for known vulnerabilities using `nmap`'s
`vulners` script. By default it runs `nmap -sV --script vulners 127.0.0.1`.
The vulnerability scan relies on the `nmap` command line tool and the
`python-nmap` library.

Run it with:

```bash
python3 netre.py
```

### Output format

The script prints a JSON object. Each section lists the command used to
collect the information and the corresponding results:

```json
{
  "ip_addresses": {
    "command": "ip -j addr",
    "results": []
  },
  "open_ports": {
    "command": "ss -tuln",
    "results": []
  },
  "running_services": {
    "command": "systemctl list-units --type=service --state=running --no-pager --no-legend",
    "results": []
  },
  "vulnerabilities": {
    "command": "nmap -sV --script vulners 127.0.0.1",
    "results": []
  }
}
```

If a command used by the script is missing, that section will also include an
`error` field describing what needs to be installed.

### Requirements (nmap, python3-nmap)

Install the following packages on Ubuntu/Debian systems:

```bash
sudo apt-get install nmap python3-nmap
```

The script will still run even if these packages are missing. In that case the
JSON output will include an error stating that `nmap` needs to be installed and
the vulnerabilities list will be empty.

### Compatibility of commands

| Platform | IP addresses (`ip`, `ipconfig`, `ifconfig`) | Open ports (`ss`, `netstat`, `lsof`) | Services (`systemctl`, `sc`) | Vulnerability scan (`nmap`) |
|----------|--------------|------------|----------|--------------------|
| Linux    | `ip`         | `ss`       | `systemctl` | `nmap` |
| Windows  | `ipconfig`   | `netstat`  | `sc`     | `nmap` |
| macOS    | `ifconfig`   | `lsof`     | not supported | `nmap` |
