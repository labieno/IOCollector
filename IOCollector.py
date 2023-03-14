# IOCollector.py
import argparse
import os
import sys
from urllib.parse import urlparse
import requests
import re
import validators
import tld
import src.scraperIOC as scraperIOC
import src.craftingIOC as craftingIOC


"""
Functions:
    debugging(url) -> Creates txt files with get request

    scrapingIOCs(reportURL, IOC_name) -> custom function for scraping reports (html); creates 4 txt files

    scrapingIOCsPARSER(reportURL, IOC_name) -> GET domains, ips, urls, hashes from reportURL with IOCparser API; creates 4 txt files
        createLists (IOC_name, response) -> Create lists of domains, ips, urls, hashes in C/USERS/username/Downloads/IOC_name

    createIOC(IOC_name) -> Create .ioc files from IOC_name directory and lists of domains, ips, urls and hashes.

    twitterCollector(account)


Examples:
    https://securelist.com/vilerat-deathstalkers-continuous-strike/107075/
    https://securelist.com/kimsukys-golddragon-cluster-and-its-c2-operations/107258/
    https://unit42.paloaltonetworks.com/cloaked-ursa-online-storage-services-campaigns/

Whitelists:
    whitelistDomains: legit domains
    whitelistURLs: legit domains (but doesn't include some, for example github.com, which can be used to malicious purposes)
"""

# To fix errors and upgrade performance
def debugging(url):
    # GET the html
    r = requests.get(url)

    # Filter defang
    defangaded = r.text.replace("[.]", ".").replace("hxxp", "http")
    splited = re.split(';|,|<|>| |\n', defangaded)
    parent_path = "C:/Users/" + os.getlogin() + "/Downloads/"
    path = os.path.join(parent_path, "debugg")
    try:
        os.mkdir(path)
        print("[+] Directory '% s' created" % path)
    except OSError as error: 
        print(error)
    
    with open(path + '/defangaded.txt', 'w') as f:
        f.write(defangaded)
    with open(path + '/splited.txt', 'w') as f:
        for l in splited:
            f.write(l)
            f.write("\n")


def main():
    # Program logic (Create the parser)
    parser = argparse.ArgumentParser(prog = 'IOCollector',
                                        #usage = '%(prog)s [options] URL/IOC_name',
                                        description = 'Specify the URL of a report to gather IOCs and create .ioc files with the OpenIOC format.\nYou can also use the IOCParser API from https://iocparser.com/',
                                        epilog = 'IOC Generator 0.4 Version')

    parser.version = 'IOC Generator 0.4 Version'
    parser.add_argument('-v',
                        '--version',
                        action='version',
                        help='display current version')

    # For exclusivity
    group = parser.add_mutually_exclusive_group(required=True)

    # Arguments
    group.add_argument('-u',
                        metavar='url',
                        type=str,
                        help='the URL of a report',
                        action='store',
                        nargs=1)

    parser.add_argument('-i',
                        metavar='IOC_name',
                        type=str,
                        help='the name of your IOC',
                        action='store',
                        nargs=1)

    group.add_argument('-c',
                        metavar='IOC_name',
                        type=str,
                        help='specify the name for the .ioc',
                        action='store',
                        nargs=1)

    parser.add_argument('-p',
                        help='Use the IOCParser API (by default it uses a custom scraping function)',
                        action='store_true')

    parser.add_argument('-d',
                        help='Show parsed html for debugging purposes.',
                        action='store_true')

    # Execute the parse_args() method to look up the arguments an process them
    args = parser.parse_args()

    # Execute tool
    if args.c:
        craftingIOC.createIOC(args.c[0])
        print("[+] Creating .ioc files...")
    elif args.u:
        if args.i:
            if args.p:
                print("[+] Scraping with IOCParser API...")
                scraperIOC.scrapingIOCsPARSER(args.u[0], args.i[0])
                print("[+] Done!")
            else:
                print("[+] Scraping with custom function...")
                scraperIOC.scrapingIOCs(args.u[0], args.i[0])
                print("[+] Done!")
        elif args.d:
            print("Debugging... Creating txt files with get request of the URL...")
            debugging(args.u[0])
            print("[+] Done!")
        else:
            print("[x] Error! Specify the name for the IOC folder")
            sys.exit()
    else:
        print("algo va mal")


if __name__ == "__main__":
    main()
