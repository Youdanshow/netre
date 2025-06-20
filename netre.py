import subprocess
import json
import platform
from typing import List, Dict

try:
    import nmap  # type: ignore
except Exception:
    nmap = None

OS = platform.system()


def get_ip_addresses():
    command = ''
    ips = []
    try:
        if OS == 'Linux':
            command = 'ip -j addr'
            output = subprocess.check_output(['ip', '-j', 'addr'], text=True)
            data = json.loads(output)
            for iface in data:
                for addr in iface.get('addr_info', []):
                    ip = addr.get('local')
                    if ip:
                        ips.append({'interface': iface.get('ifname'), 'ip': ip})
        elif OS == 'Windows':
            command = 'ipconfig'
            output = subprocess.check_output(['ipconfig'], text=True)
            for line in output.splitlines():
                line = line.strip()
                if line.startswith('IPv4'):
                    parts = line.split(':')
                    if len(parts) == 2:
                        ips.append({'interface': 'unknown', 'ip': parts[1].strip()})
        elif OS == 'Darwin':
            command = 'ifconfig'
            output = subprocess.check_output(['ifconfig'], text=True)
            for line in output.splitlines():
                line = line.strip()
                if line.startswith('inet ') and '127.0.0.1' not in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        ips.append({'interface': 'unknown', 'ip': parts[1]})
    except Exception:
        pass
    return {'command': command, 'results': ips}


def get_open_ports():
    command = ''
    ports = []
    try:
        if OS == 'Linux':
            command = 'ss -tuln'
            output = subprocess.check_output(['ss', '-tuln'], text=True)
            for line in output.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    proto = parts[0]
                    local_addr = parts[4]
                    ports.append({'protocol': proto, 'local_address': local_addr})
        elif OS == 'Windows':
            command = 'netstat -ano'
            output = subprocess.check_output(['netstat', '-ano'], text=True)
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 5 and (parts[0].startswith('TCP') or parts[0].startswith('UDP')):
                    proto = parts[0]
                    local_addr = parts[1]
                    ports.append({'protocol': proto, 'local_address': local_addr})
        elif OS == 'Darwin':
            command = 'lsof -i -nP'
            output = subprocess.check_output(['lsof', '-i', '-nP'], text=True)
            for line in output.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 9:
                    proto = parts[7]
                    local_addr = parts[8]
                    ports.append({'protocol': proto, 'local_address': local_addr})
    except Exception:
        pass
    return {'command': command, 'results': ports}


def get_running_services():
    command = ''
    services = []
    try:
        if OS == 'Linux':
            command = 'systemctl list-units --type=service --state=running --no-pager --no-legend'
            output = subprocess.check_output(
                ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--no-legend'],
                text=True,
            )
            for line in output.splitlines():
                parts = line.split()
                if parts:
                    service = parts[0]
                    services.append(service)
        elif OS == 'Windows':
            command = 'sc query state=running'
            output = subprocess.check_output(['sc', 'query', 'state=running'], text=True)
            for line in output.splitlines():
                line = line.strip()
                if line.startswith('SERVICE_NAME:'):
                    services.append(line.split(':', 1)[1].strip())
    except Exception:
        pass
    return {'command': command, 'results': services}


def scan_vulnerabilities(target: str = '127.0.0.1') -> Dict[str, List[Dict[str, str]]]:
    """Run nmap with the vulners script and return detected vulnerabilities."""
    command = 'nmap -sV --script vulners'
    if nmap is None:
        return {'command': command, 'results': []}
    vulns: List[Dict[str, str]] = []
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sV --script vulners')
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    script_results = nm[host][proto][port].get('script', {})
                    if not script_results:
                        continue
                    out = script_results.get('vulners')
                    if not out:
                        continue
                    for line in out.splitlines():
                        parts = line.split()
                        if len(parts) >= 3 and parts[0].startswith('CVE-'):
                            vulns.append(
                                {
                                    'port': str(port),
                                    'cve': parts[0],
                                    'cvss': parts[1],
                                    'link': parts[2],
                                }
                            )
    except Exception:
        pass
    return {'command': command, 'results': vulns}


def main():
    data = {
        'ip_addresses': get_ip_addresses(),
        'open_ports': get_open_ports(),
        'running_services': get_running_services(),
        'vulnerabilities': scan_vulnerabilities(),
    }
    print(json.dumps(data, indent=2))


if __name__ == '__main__':
    main()
