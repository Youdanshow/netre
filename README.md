# netre - net read

## netre.py

This Python script summarizes network and system information on the host machine. On Linux it relies on `ip`, `ss`, `systemctl`, `df`, `free` and `uptime`. On Windows it uses `ipconfig`, `netstat` and `wmic`, while macOS support falls back to `ifconfig`, `lsof`, `vm_stat` and `uptime`.


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
  "disk_usage": {
    "command": "df -h",
    "results": []
  },
  "memory": {
    "command": "free -h",
    "results": []
  },
  "uptime": {
    "command": "uptime -p",
    "results": []
  },
}
```

If a command used by the script is missing, that section will also include an
`error` field describing what needs to be installed.


### Compatibility of commands

| Platform | IP addresses (`ip`, `ipconfig`, `ifconfig`) | Open ports (`ss`, `netstat`, `lsof`) | Services (`systemctl`, `sc`) | Disk usage (`df`, `wmic`) | Memory (`free`, `wmic`, `vm_stat`) | Uptime (`uptime`, `wmic`) |
|----------|--------------|------------|----------|-------------------|--------------------|--------------------|
| Linux    | `ip`         | `ss`       | `systemctl` | `df` | `free` | `uptime` |
| Windows  | `ipconfig`   | `netstat`  | `sc` | `wmic` | `wmic` | `wmic` |
| macOS    | `ifconfig`   | `lsof`     | not supported | `df` | `vm_stat` | `uptime` |

## netre.c (C version)
This repository also includes a basic C implementation using the [Jansson](https://digip.org/jansson/) library for JSON handling.
It gathers the same data as the Python script, including disk usage, memory statistics and uptime.
Execution time is measured with a monotonic clock so the printed duration reflects
real wall-clock time rather than CPU usage.

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
