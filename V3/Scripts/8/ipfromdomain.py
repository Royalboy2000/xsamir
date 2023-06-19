#!/usr/bin/env python3
# ReaperCloudFlareBypass and rember BE GOOD AND IF YOUR GOING TO BE BAD DO IT WELL

import os
import sys
import argparse
import subprocess
import requests
import socket
from colorama import Fore, Style
from ipwhois import IPWhois

# List of common subdomains to check Feel free to modify at will ;)
SUBDOMAINS = [
    '1',
    '1rer',
    '2',
    '2tty',
    'crm',
    'dashboard',
    'db',
    'download',
    'enroll',
    'help',
    'login',
    'media',
    'mysql',
    'my',
    'ntp',
    'office',
    'partner',
    'payment',
    'qa',
    'search',
    'stats',
    'status',
    'svn',
    'test1',
    'test2',
    'test3',
    'video',
    'wiki',
    'prueba',
    'admin',
    'api',
    'app',
    'bbs',
    'blog',
    'cdn',
    'cloud',
    'demo',
    'dev',
    'devel',
    'development',
    'doc',
    'docs',
    'documentation',
    'email',
    'exchange',
    'file',
    'files',
    'forum',
    'ftp',
    'gate',
    'gateway',
    'gov',
    'govyty',
    'gw',
    'hgfgdf',
    'host',
    'image',
    'images',
    'img',
    'lkjkui',
    'm',
    'mail',
    'mail1',
    'mail2',
    'mx',
    'mx1',
    'news',
    'ns',
    'ns1',
    'ns2',
    'owa',
    'pop',
    'pop3',
    'portal',
    'remote',
    'secure',
    'server',
    'shop',
    'smtp',
    'staging',
    'store',
    'support',
    'test',
    'ticket',
    'ticketing',
    'vpn',
    'vps',
    'web',
    'webmail',
    'ww1',
    'ww42',
    'www2',
]

def check_tools():

    required_tools = ['dig', 'curl', 'whois']
    for tool in required_tools:
        if not subprocess.getoutput(f"command -v {tool}"):
            print(f"{Fore.RED}ERROR: \"{tool}\" command not found{Style.RESET_ALL}")
            sys.exit()

def print_banner():
    print(f"{Fore.RED}      R34P3R let´s get those ips and remember try to be good and if your going to be bad do it well       {Style.RESET_ALL}")
    print("")

def get_subdomains(domain):
    subdomains = []
    for subdomain in SUBDOMAINS:
        subdomains.append(subdomain + '.' + domain)
    return subdomains

def check_domain(domain):
    if not subprocess.getoutput(f"dig +short {domain}"):
        if not "Domain Name:" in subprocess.getoutput(f"whois {domain}"):
            print(f"{Fore.RED}ERROR: Domain not found{Style.RESET_ALL}")
            sys.exit()

def dig_domain(domain):
    print(f"{Fore.BLUE} INFO: Checking {domain}{Style.RESET_ALL}")
    subdomains = get_subdomains(domain)
    for subdomain in subdomains:
        try:
            ip = socket.gethostbyname(subdomain)
            vendor = get_vendor(ip)
            dns = socket.getfqdn(ip)
            print(f"{Fore.GREEN}   + {ip} ({dns}) [{vendor}]{Style.RESET_ALL}")
        except socket.error:
            pass

def get_vendor(ip):
    curl_command = f"curl -s 'https://rdap.arin.net/registry/ip/{ip}' -H 'User-Agent: Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Mobile Safari/537.36' --compressed"
    output = subprocess.getoutput(curl_command)
    for line in output.splitlines():
        line = line.strip()
        if '"name"' in line:
            vendor = line.split(":")[1].replace('"', '').strip()
            return vendor
    return "Unknown"

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ReaperCloudFlareBypass')
    parser.add_argument('-v', '--domain', help='Domain to scan', required=True)
    parser.add_argument('-vv', '--verbose', help='Increase verbosity', action='count', default=0)
    args = parser.parse_args()

    check_tools()
    print_banner()
    check_domain(args.domain)
    dig_domain(args.domain)
