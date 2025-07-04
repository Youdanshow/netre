#!/bin/sh

# Minimal shell version of netre
# Sequentially runs standard system commands
# and prints their outputs.

# IP addresses
echo "### IP addresses"
if command -v ip >/dev/null 2>&1; then
    ip -j addr
elif command -v ipconfig >/dev/null 2>&1; then
    ipconfig
elif command -v ifconfig >/dev/null 2>&1; then
    ifconfig
else
    echo "no IP address command"
fi

echo
# Open ports
echo "### Open ports"
if command -v ss >/dev/null 2>&1; then
    ss -tuln
elif command -v netstat >/dev/null 2>&1; then
    netstat -ano
elif command -v lsof >/dev/null 2>&1; then
    lsof -i -nP
else
    echo "no open port command"
fi

echo
# Running services
echo "### Running services"
if command -v systemctl >/dev/null 2>&1; then
    systemctl list-units --type=service --state=running --no-pager --no-legend
elif command -v sc >/dev/null 2>&1; then
    sc query state=running
else
    echo "no service command"
fi

echo
# Disk usage
echo "### Disk usage"
if command -v df >/dev/null 2>&1; then
    df -h
elif command -v wmic >/dev/null 2>&1; then
    wmic logicaldisk get size,freespace,caption
else
    echo "no disk usage command"
fi

echo
# Memory usage
echo "### Memory usage"
if command -v free >/dev/null 2>&1; then
    free -h
elif command -v wmic >/dev/null 2>&1; then
    wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /Value
elif command -v vm_stat >/dev/null 2>&1; then
    vm_stat
else
    echo "no memory command"
fi

echo
# Uptime
echo "### Uptime"
if command -v uptime >/dev/null 2>&1; then
    uptime -p
elif command -v wmic >/dev/null 2>&1; then
    wmic os get lastbootuptime
else
    echo "no uptime command"
fi
