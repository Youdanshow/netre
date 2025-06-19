import subprocess
import json


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


def main():
    data = {
        'ip_addresses': get_ip_addresses(),
        'open_ports': get_open_ports(),
        'running_services': get_running_services(),
    }
    print(json.dumps(data, indent=2))


if __name__ == '__main__':
    main()
