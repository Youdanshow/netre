# netre (ip, ss, systemctl, ipconfig, netstat, ifconfig, lsof, sc, nmap)
Net read - a project that scan you server and resume you all vulnerability and how to patch them

## netre.py (uses `ip`, `ss`, `systemctl`, `ipconfig`, `netstat`, `ifconfig`, `lsof`, `sc`, `nmap`)

This Python script summarizes network information on the host system. On Linux it relies on `ip`, `ss` and `systemctl`. On Windows it uses `ipconfig` and `netstat`, while macOS support falls back to `ifconfig` and `lsof`.

It can also scan the local host for known vulnerabilities using `nmap`'s
`vulners` script. By default it runs `nmap -sV --script vulners 127.0.0.1`.
The vulnerability scan relies on the `nmap` command line tool.

Run it with:

```bash
python3 netre.py
```

While running, the script prints a progress bar to `stderr`. The last
`#` in the bar blinks so you can easily see the current progress, and it
stops blinking when all tasks complete. The script then displays the
total time before printing the JSON output.

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

### Requirements (nmap)

Install the following packages on Ubuntu/Debian systems:

```bash
sudo apt-get install nmap
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

## netre.c (C version)
This repository also includes a basic C implementation using the [Jansson](https://digip.org/jansson/) library for JSON handling.

Compile it with the provided Makefile:

```bash
sudo apt install libjansson-dev
make
```

Run with:

```bash
./netre
```

The output format matches the Python script, but features depend on the commands available on the host.
