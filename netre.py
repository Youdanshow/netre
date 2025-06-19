import subprocess
import json
from typing import List, Dict

try:
    import nmap  # type: ignore
except Exception:
    nmap = None


def get_ip_addresses():
    try:
        output = subprocess.check_output(['ip', '-j', 'addr'], text=True)
        data = json.loads(output)
        ips = []
        for iface in data:
            for addr in iface.get('addr_info', []):
                ip = addr.get('local')
                if ip:
                    ips.append({'interface': iface.get('ifname'), 'ip': ip})
        return ips
    except Exception as e:
        return []


def get_open_ports():
    ports = []
    try:
        output = subprocess.check_output(['ss', '-tuln'], text=True)
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0]
                local_addr = parts[4]
                ports.append({'protocol': proto, 'local_address': local_addr})
    except Exception:
        pass
    return ports


def get_running_services():
    services = []
    try:
        output = subprocess.check_output(
            ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--no-legend'],
            text=True,
        )
        for line in output.splitlines():
            parts = line.split()
            if parts:
                service = parts[0]
                services.append(service)
    except Exception:
        pass
    return services


def scan_vulnerabilities(target: str = '127.0.0.1') -> List[Dict[str, str]]:
    """Run nmap with the vulners script and return detected vulnerabilities."""
    if nmap is None:
        return []
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
    return vulns


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
