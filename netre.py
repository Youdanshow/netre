import subprocess
import json
import platform
import shutil
import sys
import time
import datetime
from typing import List, Dict

try:
    import nmap  # type: ignore
except Exception:
    nmap = None

OS = platform.system()


def command_available(cmd: str) -> bool:
    """Return True if the given command is available on the system."""
    return shutil.which(cmd) is not None


def get_ip_addresses():
    command = ''
    error = None
    ips = []
    try:
        if OS == 'Linux':
            command = 'ip -j addr'
            if not command_available('ip'):
                error = 'ip needs to be installed'
            else:
                output = subprocess.check_output(
                    ['ip', '-j', 'addr'], text=True, stderr=subprocess.DEVNULL
                )
                data = json.loads(output)
                for iface in data:
                    for addr in iface.get('addr_info', []):
                        ip = addr.get('local')
                        if ip:
                            ips.append({'interface': iface.get('ifname'), 'ip': ip})
        elif OS == 'Windows':
            command = 'ipconfig'
            if not command_available('ipconfig'):
                error = 'ipconfig needs to be installed'
            else:
                output = subprocess.check_output(
                    ['ipconfig'], text=True, stderr=subprocess.DEVNULL
                )
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith('IPv4'):
                        parts = line.split(':')
                        if len(parts) == 2:
                            ips.append({'interface': 'unknown', 'ip': parts[1].strip()})
        elif OS == 'Darwin':
            command = 'ifconfig'
            if not command_available('ifconfig'):
                error = 'ifconfig needs to be installed'
            else:
                output = subprocess.check_output(
                    ['ifconfig'], text=True, stderr=subprocess.DEVNULL
                )
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith('inet ') and '127.0.0.1' not in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            ips.append({'interface': 'unknown', 'ip': parts[1]})
    except Exception:
        pass
    result = {'command': command, 'results': ips}
    if error:
        result['error'] = error
    return result


def get_open_ports():
    command = ''
    error = None
    ports = []
    try:
        if OS == 'Linux':
            command = 'ss -tuln'
            if not command_available('ss'):
                error = 'ss needs to be installed'
            else:
                output = subprocess.check_output(
                    ['ss', '-tuln'], text=True, stderr=subprocess.DEVNULL
                )
                for line in output.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 5:
                        proto = parts[0]
                        local_addr = parts[4]
                        ports.append({'protocol': proto, 'local_address': local_addr})
        elif OS == 'Windows':
            command = 'netstat -ano'
            if not command_available('netstat'):
                error = 'netstat needs to be installed'
            else:
                output = subprocess.check_output(
                    ['netstat', '-ano'], text=True, stderr=subprocess.DEVNULL
                )
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and (parts[0].startswith('TCP') or parts[0].startswith('UDP')):
                        proto = parts[0]
                        local_addr = parts[1]
                        ports.append({'protocol': proto, 'local_address': local_addr})
        elif OS == 'Darwin':
            command = 'lsof -i -nP'
            if not command_available('lsof'):
                error = 'lsof needs to be installed'
            else:
                output = subprocess.check_output(
                    ['lsof', '-i', '-nP'], text=True, stderr=subprocess.DEVNULL
                )
                for line in output.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 9:
                        proto = parts[7]
                        local_addr = parts[8]
                        ports.append({'protocol': proto, 'local_address': local_addr})
    except Exception:
        pass
    result = {'command': command, 'results': ports}
    if error:
        result['error'] = error
    return result


def get_running_services():
    command = ''
    error = None
    services = []
    try:
        if OS == 'Linux':
            command = 'systemctl list-units --type=service --state=running --no-pager --no-legend'
            if not command_available('systemctl'):
                error = 'systemctl needs to be installed'
            else:
                output = subprocess.check_output(
                    ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--no-legend'],
                    text=True,
                    stderr=subprocess.DEVNULL,
                )
                for line in output.splitlines():
                    parts = line.split()
                    if parts:
                        service = parts[0]
                        services.append(service)
        elif OS == 'Windows':
            command = 'sc query state=running'
            if not command_available('sc'):
                error = 'sc needs to be installed'
            else:
                output = subprocess.check_output(
                    ['sc', 'query', 'state=running'], text=True, stderr=subprocess.DEVNULL
                )
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith('SERVICE_NAME:'):
                        services.append(line.split(':', 1)[1].strip())
    except Exception:
        pass
    result = {'command': command, 'results': services}
    if error:
        result['error'] = error
    return result


def get_disk_usage():
    command = ''
    error = None
    disks = []
    try:
        if OS in ('Linux', 'Darwin'):
            command = 'df -h'
            if not command_available('df'):
                error = 'df needs to be installed'
            else:
                output = subprocess.check_output(
                    ['df', '-h'], text=True, stderr=subprocess.DEVNULL
                )
                for line in output.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        disks.append(
                            {
                                'filesystem': parts[0],
                                'size': parts[1],
                                'used': parts[2],
                                'available': parts[3],
                                'use%': parts[4],
                                'mount': parts[5],
                            }
                        )
        elif OS == 'Windows':
            command = 'wmic logicaldisk get size,freespace,caption'
            if not command_available('wmic'):
                error = 'wmic needs to be installed'
            else:
                output = subprocess.check_output(
                    ['wmic', 'logicaldisk', 'get', 'size,freespace,caption'],
                    text=True,
                    stderr=subprocess.DEVNULL,
                )
                for line in output.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) == 3:
                        caption, free, size = parts
                        try:
                            size_i = int(size)
                            free_i = int(free)
                            used_i = size_i - free_i
                            usage = f"{100 * used_i / size_i:.1f}%" if size_i > 0 else '0%'
                            disks.append(
                                {
                                    'filesystem': caption,
                                    'size': str(size_i),
                                    'used': str(used_i),
                                    'available': str(free_i),
                                    'use%': usage,
                                    'mount': caption,
                                }
                            )
                        except Exception:
                            pass
    except Exception:
        pass

    result = {'command': command, 'results': disks}
    if error:
        result['error'] = error
    return result


def get_memory_usage():
    command = ''
    error = None
    mem = []
    try:
        if OS == 'Linux':
            command = 'free -h'
            if not command_available('free'):
                error = 'free needs to be installed'
            else:
                output = subprocess.check_output(
                    ['free', '-h'], text=True, stderr=subprocess.DEVNULL
                )
                for line in output.splitlines():
                    lower = line.lower()
                    if lower.startswith('mem:') or lower.startswith('mem '):
                        parts = line.split()
                        if len(parts) >= 4:
                            mem.append(
                                {
                                    'total': parts[1],
                                    'used': parts[2],
                                    'free': parts[3],
                                }
                            )
        elif OS == 'Windows':
            command = 'wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /Value'
            if not command_available('wmic'):
                error = 'wmic needs to be installed'
            else:
                output = subprocess.check_output(
                    ['wmic', 'OS', 'get', 'FreePhysicalMemory,TotalVisibleMemorySize', '/Value'],
                    text=True,
                    stderr=subprocess.DEVNULL,
                )
                vals = {}
                for line in output.splitlines():
                    if '=' in line:
                        k, v = line.split('=', 1)
                        vals[k.strip()] = v.strip()
                try:
                    total_kb = int(vals.get('TotalVisibleMemorySize', '0'))
                    free_kb = int(vals.get('FreePhysicalMemory', '0'))
                    used_kb = total_kb - free_kb
                    mem.append(
                        {
                            'total': f"{total_kb // 1024}M",
                            'used': f"{used_kb // 1024}M",
                            'free': f"{free_kb // 1024}M",
                        }
                    )
                except Exception:
                    pass
        elif OS == 'Darwin':
            command = 'vm_stat'
            if not command_available('vm_stat'):
                error = 'vm_stat needs to be installed'
            else:
                output = subprocess.check_output(['vm_stat'], text=True, stderr=subprocess.DEVNULL)
                page_size = 4096
                stats = {}
                for line in output.splitlines():
                    if ':' in line:
                        k, v = line.split(':')
                        stats[k.strip()] = int(v.strip().strip('.')) * page_size
                free = stats.get('Pages free', 0)
                used = stats.get('Pages active', 0) + stats.get('Pages inactive', 0)
                total = used + free
                if total > 0:
                    mem.append(
                        {
                            'total': f"{total // (1024 * 1024)}M",
                            'used': f"{used // (1024 * 1024)}M",
                            'free': f"{free // (1024 * 1024)}M",
                        }
                    )
    except Exception:
        pass

    result = {'command': command, 'results': mem}
    if error:
        result['error'] = error
    return result


def get_uptime():
    command = ''
    error = None
    up = []
    try:
        if OS in ('Linux', 'Darwin'):
            command = 'uptime -p'
            if not command_available('uptime'):
                error = 'uptime needs to be installed'
            else:
                output = subprocess.check_output(
                    ['uptime', '-p'], text=True, stderr=subprocess.DEVNULL
                )
                up.append(output.strip())
        elif OS == 'Windows':
            command = 'wmic os get lastbootuptime'
            if not command_available('wmic'):
                error = 'wmic needs to be installed'
            else:
                output = subprocess.check_output(
                    ['wmic', 'os', 'get', 'lastbootuptime'],
                    text=True,
                    stderr=subprocess.DEVNULL,
                )
                boot = ''
                for line in output.splitlines():
                    line = line.strip()
                    if line and 'LastBootUpTime' not in line:
                        boot = line
                        break
                if boot:
                    try:
                        boot_dt = datetime.datetime.strptime(
                            boot.split('.')[0], '%Y%m%d%H%M%S'
                        )
                        diff = datetime.datetime.now() - boot_dt
                        days = diff.days
                        hours, rem = divmod(diff.seconds, 3600)
                        minutes = rem // 60
                        up.append(
                            f"{days} days, {hours} hours, {minutes} minutes"
                        )
                    except Exception:
                        pass
    except Exception:
        pass

    result = {'command': command, 'results': up}
    if error:
        result['error'] = error
    return result


def scan_vulnerabilities(target: str = '127.0.0.1') -> Dict[str, List[Dict[str, str]]]:
    """Run nmap with the vulners script and return detected vulnerabilities."""
    command = f'nmap -sV --script vulners {target}'
    error = None

    if not command_available('nmap'):
        error = 'nmap needs to be installed'
        return {'command': command, 'results': [], 'error': error}

    vulns: List[Dict[str, str]] = []
    try:
        output = subprocess.check_output(
            ['nmap', '-sV', '--script', 'vulners', target],
            text=True,
            errors='ignore',
            stderr=subprocess.DEVNULL,
        )
        lines = output.splitlines()
        current_port = ''
        collecting = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('| vulners:'):
                collecting = True
                continue

            if collecting:
                if not stripped.startswith('|'):
                    collecting = False
                    continue
                content = stripped.lstrip('|').strip()
                parts = content.split()
                if len(parts) >= 3 and parts[0].startswith('CVE-'):
                    vulns.append(
                        {
                            'port': current_port,
                            'cve': parts[0],
                            'cvss': parts[1],
                            'link': parts[2],
                        }
                    )
            else:
                if '/tcp' in stripped or '/udp' in stripped:
                    current_port = stripped.split()[0].split('/')[0]
    except Exception:
        pass

    result: Dict[str, List[Dict[str, str]]] = {
        'command': command,
        'results': vulns,
    }
    if error:
        result['error'] = error
    return result


def main():
    print("loading...", file=sys.stderr, flush=True)

    tasks = [
        ('ip_addresses', get_ip_addresses),
        ('open_ports', get_open_ports),
        ('running_services', get_running_services),
        ('disk_usage', get_disk_usage),
        ('memory', get_memory_usage),
        ('uptime', get_uptime),
        ('vulnerabilities', scan_vulnerabilities),
    ]

    start_time = time.time()
    total = len(tasks)
    data: Dict[str, Dict[str, List[Dict[str, str]]]] = {}

    for i, (name, func) in enumerate(tasks, 1):
        data[name] = func()
        filled = int(30 * i / total)
        if filled > 0:
            if i < total:
                bar_chars = '#' * (filled - 1) + '\033[5m#\033[0m'
            else:
                bar_chars = '#' * filled
        else:
            bar_chars = ''
        bar = '[' + bar_chars + ' ' * (30 - filled) + ']'
        print(f"\r{bar} {i}/{total}", file=sys.stderr, end='', flush=True)

    elapsed = time.time() - start_time
    print(f"\nCompleted in {elapsed:.2f} seconds", file=sys.stderr)

    print(json.dumps(data, indent=2))


if __name__ == '__main__':
    main()
