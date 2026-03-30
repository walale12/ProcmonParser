import pandas as pd
import re
import ipaddress as ip
import os
import sys
import socket
from tqdm import tqdm
import argparse as arg
import bisect
import pyasn

def parse_args():
    parser = arg.ArgumentParser()
    parser.add_argument('file', help='Path to the log file')
    parser.add_argument("-dc", "--check-datacentre", help="Automatically check IP addresses to see if they are in ranges used by datacentres", action="store_true")
    return parser.parse_args()

def process_dc_list():
    print("Downloading lists of datacentre IP ranges...")
    datacentre_ranges_1 = pd.read_csv('https://raw.githubusercontent.com/client9/ipcat/master/datacenters.csv', header=0, names=['hostmin', 'hostmax', 'vendor', 'url'])
    datacentre_ranges_1.drop(columns=['url'], inplace=True)
    datacentre_ranges_1.replace('Google App Engine', 'Google', inplace=True)
    datacentre_ranges_1.replace('Amazon AWS', 'Amazon', inplace=True)
    datacentre_ranges_1.replace('Microsoft Azure', 'Microsoft', inplace=True)
    datacentre_ranges_2 = pd.read_csv('https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv', header = 1, names = ['cidr', 'hostmin', 'hostmax', 'vendor'])
    datacentre_ranges_2.drop(columns=['cidr'], inplace=True)
    datacentre_ranges_2.replace('GCP', 'Google', inplace=True)
    datacentre_ranges_2.replace('AWS', 'Amazon', inplace=True)
    datacentre_ranges_2.replace('Azure', 'Microsoft', inplace=True)
    datacentre_ranges_2.replace('CloudFlare', 'Cloudflare', inplace=True)
    print("Processing lists...")
    datacentre_ranges_1['int_hostmin'] = datacentre_ranges_1['hostmin'].apply(lambda x: int(ip.ip_address(x)))
    datacentre_ranges_1['int_hostmax'] = datacentre_ranges_1['hostmax'].apply(lambda x: int(ip.ip_address(x)))
    datacentre_ranges_2['int_hostmin'] = datacentre_ranges_2['hostmin'].apply(lambda x: int(ip.ip_address(x)))
    datacentre_ranges_2['int_hostmax'] = datacentre_ranges_2['hostmax'].apply(lambda x: int(ip.ip_address(x)))
    print("Sorting lists...")
    datacentre_ranges_1.sort_values(by=['int_hostmin'], inplace=True)
    datacentre_ranges_2.sort_values(by=['int_hostmin'], inplace=True)
    datacentre_starts_1 = datacentre_ranges_1['int_hostmin'].tolist()
    datacentre_ends_1 = datacentre_ranges_1['int_hostmax'].tolist()
    datacentre_vendors_1 = datacentre_ranges_1['vendor'].tolist()
    datacentre_starts_2 = datacentre_ranges_2['int_hostmin'].tolist()
    datacentre_ends_2 = datacentre_ranges_2['int_hostmax'].tolist()
    datacentre_vendors_2 = datacentre_ranges_2['vendor'].tolist()
    print("List processing complete.")
    return [datacentre_starts_1, datacentre_ends_1, datacentre_vendors_1, datacentre_starts_2, datacentre_ends_2, datacentre_vendors_2]

def datacentre_check(ip_addresses):
    range_lists = process_dc_list()
    found_datacentre_ips = pd.DataFrame(columns=['ip_address', 'host'])
    found_residential_ips = pd.DataFrame(columns=['ip_address'])
    print("Checking found IP addresses against datacentre ranges...")
    for ip_address in tqdm(ip_addresses, unit='addresses'):
        vendor = ip_datacentre(ip_address, range_lists)
        if vendor:
            new_datacentre_row = pd.DataFrame({'ip_address': ip_address, 'host': vendor}, index=[0])
            found_datacentre_ips = pd.concat([found_datacentre_ips, new_datacentre_row])
        else:
            new_residential_row = pd.DataFrame({'ip_address': ip_address}, index=[0])
            found_residential_ips = pd.concat([found_residential_ips, new_residential_row])
    print("Finished checking datacentre ranges. Now checking ASN information for remaining IP addresses...")
    asn_ips = check_asn(found_residential_ips)
    print("IP address checks complete.")
    found_datacentre_ips = pd.concat([found_datacentre_ips, asn_ips[0]])
    found_residential_ips = asn_ips[1]
    return [found_datacentre_ips, found_residential_ips]

def check_asn(ip_address_frame):
    asndb = pyasn.pyasn('ipasn_db')
    asn_datacentre_ips = pd.DataFrame(columns=['ip_address', 'host'])
    asn_residential_ips = pd.DataFrame(columns=['ip_address'])
    for ip_address in tqdm(ip_address_frame.ip_address, unit='addresses'):
        asn_response = asndb.lookup(ip_address)
        vendor = asn_lookup(asn_response[0])
        if vendor:
            new_datacentre_row = pd.DataFrame({'ip_address': ip_address, 'host': vendor}, index=[0])
            asn_datacentre_ips = pd.concat([asn_datacentre_ips, new_datacentre_row])
        else:
            new_residential_row = pd.DataFrame({'ip_address': ip_address}, index=[0])
            asn_residential_ips = pd.concat([asn_residential_ips, new_residential_row])
    return [asn_datacentre_ips, asn_residential_ips]


def asn_lookup(asn):
    df = pd.read_csv('known_asns.csv')
    vendor = df.query("ASN == @asn")
    if not vendor.empty:
        return vendor['Vendor'].values[0]
    return None

def ip_datacentre(ip_address, datacentre_ranges):
    ip_address = ip.ip_address(ip_address)
    ip_address = int(ip_address)
    index = bisect.bisect_left(datacentre_ranges[0], ip_address)
    index -= 1
    if datacentre_ranges[0][index] <= ip_address <= datacentre_ranges[1][index]:
        return datacentre_ranges[2][index]
    index = bisect.bisect_left(datacentre_ranges[3], ip_address)
    index -= 1
    if datacentre_ranges[3][index] <= ip_address <= datacentre_ranges[4][index]:
        return datacentre_ranges[5][index]
    return None

def extract_ip_from_hostname(hostname: str):
    hostname = hostname.replace("ec2-", "") #removing "ec2" from AWS EC2 hostnames because it comes right before an IP address and can make the regex think it's an IP starting with "2." and dropping the last octet
    ip_dots = re.findall(r'[0-9]+(?:\.[0-9]+){3}', hostname) #regex to find IP addresses in normal format in hostnames
    if ip_dots:
        ip_dots = ip_dots[0]
        if is_valid_ip(ip_dots):
            return ip_dots
    ip_dashes = re.findall(r'[0-9]+(?:-[0-9]+){3}', hostname) #regex to find IP addresses with dashes instead of dots, as AWS likes to do in their hostnames
    if ip_dashes:
        ip_dashes = ip_dashes[0]
        ip_dashes = ip_dashes.replace('-', '.')
        if is_valid_ip(ip_dashes):
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



def path_parse(args):
    found_ips = []
    system_hostname = socket.gethostname()
    try:
        logfile = pd.read_csv(args.file)
    except pd.errors.EmptyDataError:
        print('Error: File is empty')
        sys.exit(1)
    except pd.errors.ParserError:
        print('Error: File is not a valid CSV')
        sys.exit(1)
    paths = logfile.Path
    print("Parsing log file, this may take a while...")
    for path in tqdm(paths, unit='rows'):
        path = path.split(' -> ')
        for element in path:
            if system_hostname in element or 'view-localhost' in element: #sanitising path values that we know won't contain IPs or useful hostnames
                path.remove(element)
        path = path[0]
        path = path.split(':') #separating hostnames/IP addresses from port numbers and protocols
        if is_hostname(path[0]):
            current_hostname = str(path[0])
            current_ip = extract_ip_from_hostname(current_hostname)
        else:
            if is_valid_ip(path[0]):
                current_ip = path[0]
            else:
                current_ip = None
        if current_ip and current_ip not in found_ips:
            found_ips.append(current_ip)
    if args.check_datacentre:
        separated_ips = datacentre_check(found_ips)
        print("These IP addresses are in datacentre ranges:")
        print(separated_ips[0])
        print("These IP addresses are not in known datacentre ranges, and should be further investigated:")
        print(separated_ips[1].to_string(index=False))
    else:
        print("Found IP addresses:")
        found_ips_dataframe = pd.DataFrame({'ip_address': found_ips})
        print(found_ips_dataframe)


if __name__ == '__main__':
    args = parse_args()
    if not os.path.isfile(args.file):
        print('Error: File does not exist')
        sys.exit(1)
    path_parse(args)