import pandas as pd
import re
import ipaddress as ip
import os
import socket
from urllib.request import urlretrieve

def get_file_name():
    current_directory = os.getcwd()
    filename = input()
    if filename not in os.listdir(current_directory):
        print('This file does not exist, please enter the name of a valid file in ' + current_directory + '/ which you would like to parse')
        filename = get_file_name()
    return filename

def ip_datacentre(ip_address: str, datacentre_list):
    for i in range(len(datacentre_list)):
        if ip.ip_address(ip_address) in ip.ip_network(datacentre_list[i][0]):
            return datacentre_list[i][1]
    return None

def extract_ip_from_hostname(hostname: str):
    hostname = hostname.replace("ec2-", "") #removing "ec2" from AWS EC2 hostnames because it comes right before an IP address and can make the regex think it's an IP starting with "2." and dropping the last octet
    ip_dots = re.findall(r'[0-9]+(?:\.[0-9]+){3}',hostname)[0]
    if ip_dots and is_valid_ip(ip_dots):
        return ip_dots
    ip_dashes = re.findall(r'[0-9]+(?:-[0-9]+){3}', hostname)[0]
    ip_dashes = ip_dashes.replace('-', '.')
    if ip_dashes and is_valid_ip(ip_dashes):
        return ip_dashes
    return None

def is_hostname(path: str):
    if re.search('[a-zA-Z]', path):
        return True
    else:
        return False

def is_valid_ip(ip_address: str):
    try:
        ip.ip_address(ip_address)
        return True
    except ValueError:
        return False

def ip_to_hostname(ip_address: str):
    hostname = socket.gethostbyaddr(ip_address)[0]
    return hostname

def hostname_to_ip(hostname: str):
    try:
        ip_address: str = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        ip_address = extract_ip_from_hostname(hostname)
        if ip_address:
            return ip_address
        else:
            return None

def path_parse():
    dc_masks_vendors = []
    found_ips = []
    found_dc_ips = []
    found_dc_vendors = []
    found_dc_hostnames = []
    found_residential_ips = []
    found_residential_hostnames = []
    system_hostname = socket.gethostname()
    logfile = pd.read_csv('LogFileCB.csv')
    datacentres = pd.read_csv('datacentres.csv')
    paths = logfile.Path
    masks = datacentres.cidr
    vendors = datacentres.vendor
    for mask in masks:
        dc_masks_vendors.append([mask, ''])
    for i, vendor in enumerate(vendors):
        dc_masks_vendors[i][1] = vendor
    for path in paths:
        path = path.split(' -> ')
        for element in path:
            if system_hostname in element or 'view-localhost' in element: #sanitising path values that we know won't contain IPs or useful hostnames
                path.remove(element)
        path = path[0]


if __name__ == '__main__':
    directory = os.getenv("USERPROFILE") + "\\Downloads\\SysInternalsSuite\\"
    os.chdir(directory)
    os.remove('datacentres.csv')
    urlretrieve('https://raw.githubusercontent.com/jhassine/server-ip-addresses/refs/heads/master/data/datacenters.csv', 'datacentres.csv')
    path_parse()