import pandas as pd
import os
import sys
import socket
from tqdm import tqdm
import argparse as arg
import sharedfunctions as shared

def parse_args():
    parser = arg.ArgumentParser()
    parser.add_argument('file', help='Path to the log file')
    parser.add_argument("-dc", "--check-datacentre", help="Automatically check IP addresses to see if they are in ranges used by datacentres", action="store_true")
    return parser.parse_args()

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
        if shared.is_hostname(path[0]):
            current_hostname = str(path[0])
            current_ip = shared.extract_ip_from_hostname(current_hostname)
        else:
            if shared.is_valid_ip(path[0]):
                current_ip = path[0]
            else:
                current_ip = None
        if current_ip and current_ip not in found_ips and not shared.is_reserved(current_ip) and not shared.is_my_ip(current_ip):
            found_ips.append(current_ip)
    if args.check_datacentre:
        separated_ips = shared.datacentre_check(found_ips)
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
    if not args.file.lower().endswith('.csv'):
        print('Error: File is not a CSV')
        sys.exit(1)
    path_parse(args)