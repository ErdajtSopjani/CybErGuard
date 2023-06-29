import argparse
import nmap
import subprocess
import sys

ascii = """
 ▄████▄▓██   ██▓ ▄▄▄▄   ▓█████  ██▀███    ▄████  █    ██  ▄▄▄       ██▀███  ▓█████▄ 
▒██▀ ▀█ ▒██  ██▒▓█████▄ ▓█   ▀ ▓██ ▒ ██▒ ██▒ ▀█▒ ██  ▓██▒▒████▄    ▓██ ▒ ██▒▒██▀ ██▌
▒▓█    ▄ ▒██ ██░▒██▒ ▄██▒███   ▓██ ░▄█ ▒▒██░▄▄▄░▓██  ▒██░▒██  ▀█▄  ▓██ ░▄█ ▒░██   █▌
▒▓▓▄ ▄██▒░ ▐██▓░▒██░█▀  ▒▓█  ▄ ▒██▀▀█▄  ░▓█  ██▓▓▓█  ░██░░██▄▄▄▄██ ▒██▀▀█▄  ░▓█▄   ▌
▒ ▓███▀ ░░ ██▒▓░░▓█  ▀█▓░▒████▒░██▓ ▒██▒░▒▓███▀▒▒▒█████▓  ▓█   ▓██▒░██▓ ▒██▒░▒████▓ 
░ ░▒ ▒  ░ ██▒▒▒ ░▒▓███▀▒░░ ▒░ ░░ ▒▓ ░▒▓░ ░▒   ▒ ░▒▓▒ ▒ ▒  ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ▒▒▓  ▒ 
  ░  ▒  ▓██ ░▒░ ▒░▒   ░  ░ ░  ░  ░▒ ░ ▒░  ░   ░ ░░▒░ ░ ░   ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ▒  ▒ 
░       ▒ ▒ ░░   ░    ░    ░     ░░   ░ ░ ░   ░  ░░░ ░ ░   ░   ▒     ░░   ░  ░ ░  ░ 
░ ░     ░ ░      ░         ░  ░   ░           ░    ░           ░  ░   ░        ░    
░       ░ ░           ░                                                      ░      
"""

print(f"\n\n\n{ascii}\n\n")

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Network scanner')
parser.add_argument('target', metavar='target', type=str, help='target IP address or hostname')
parser.add_argument('-p', '--ports', metavar='ports', type=str, default='22-443', help='ports to scan (default: 22-443)')
parser.add_argument('-m', '--metasploit', action='store_true', help='perform vulnerability scan with Metasploit after the network scan')
args = parser.parse_args()

target = args.target
ports = args.ports
use_metasploit = args.metasploit

print(f"Scanning {target} on {ports}...")

# Perform the network scan with OS and version detection
nm = nmap.PortScanner()
try:
    nm.scan(target, ports, arguments='-O -sV')
except nmap.nmap.PortScannerError as e:
    if 'requires root privileges' in str(e):
        print('\n\nError: TCP/IP fingerprinting (for OS scan) requires root privileges.')
        print('Please run the script with root privileges (e.g., using sudo).\n\n')
        sys.exit(1)
    else:
        raise e

# Print host information
for host in nm.all_hosts():
    print('\n\n\n\n----------------------------------------------------\n')
    print('Host: %s (%s)' % (host, nm[host].hostname()))
    print('State: %s' % nm[host].state())
    print('\n')
    if 'osmatch' in nm[host]:
        print('-----------------------------------------------------\n')
        print('Operating System:\n')
        for os_match in nm[host]['osmatch']:
            print('     Name: %s' % os_match['name'])
            print('     Accuracy: %s' % os_match['accuracy'])
    for proto in nm[host].all_protocols():
        print('\n-----------------------------------------------------\n')
        print('Protocol: %s\n' % proto)
        lport = list(nm[host][proto].keys())
        lport.sort()
        for port in lport:
            port_info = nm[host][proto][port]
            print('     Port: %s\tState: %s\tService: %s\tVersion: %s' % (
                port, port_info['state'], port_info['name'], port_info['version']
            ))

# Perform the vulnerability scan with Metasploit if requested
metasploit_scan = input("\n\n\nDo you want to perform a vulnerability scan with Metasploit? (y/n): ")
if metasploit_scan == "y" or use_metasploit:
    print('\n\nPerforming vulnerability scan with Metasploit...\n')
    command = f'msfconsole -q -x "use auxiliary/scanner/nmap/nmap_xml"\nset RHOSTS {target}\nset RPORTS {ports}\nrun\nexit'
    subprocess.run(command, shell=True)
else:
    print("Skipping metasploit scan...")
    sys.exit(1)
print('\n\n\n\n')
