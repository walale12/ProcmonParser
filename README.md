# Procmon IP Address Parser
The Procmon IP Address Parser is a tool to parse IP addresses from .csv files created by Procmon.

## Installation
### Requirements
- Python 3.6+
- Pandas
- Tqdm
- pyasn  

In addition, with pyasn, you will need to download the IPASN data files for ASN lookups to work. Please follow the ipasn instructions [here](https://pypi.org/project/pyasn/#description:~:text=23969%20%2E%2E%2E-,IPASN,longer), and save the file as "ipasn_db" in your Python working directory.

## Usage
To run the parser, invoke it from the command line as follows:
```bash
python procmon_ip_address_parser.py <path_to_csv_file> [-dc]
```
The `<path_to_csv_file>` argument should be the path to the CSV file you wish to parse. Procmon must have generated this .csv file, and it is recommended that filters be applied in procmon prior to saving the .csv file to ensure that time is not wasted parsing irrelevant data.

The optional `-dc` flag will tell the parser to look up each IP address and determine if it belongs to a cloud services provider.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Licence
[GPLv3.0](https://choosealicense.com/licenses/gpl-3.0/)