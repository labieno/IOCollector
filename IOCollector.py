# IOCollector.py
import argparse
import os
import sys
from urllib.parse import urlparse
import requests
import re
import validators
import tld
import urllib

"""
Functions:
    scrapingIOCs()

    scrapingIOCsPARSER(reportURL, IOC_name) -> GET domains, ips, urls, hashes from reportURL with IOCparser API.
        
        createLists (IOC_name, response) -> Create lists of domains, ips, urls, hashes in C/USERS/username/Downloads/IOC_name

    createIOC(IOC_name) -> Create .ioc files from IOC_name directory and lists of domains, ips, urls and hashes.

Examples:
    https://securelist.com/vilerat-deathstalkers-continuous-strike/107075/
    https://securelist.com/kimsukys-golddragon-cluster-and-its-c2-operations/107258/
    https://unit42.paloaltonetworks.com/cloaked-ursa-online-storage-services-campaigns/

Whitelists:
    whitelistDomains: legit domains
    whitelistURLs: legit domains (but doesn't include some, for example github.com, which can be used to malicious purposes)
"""

whitelistDomains = ["microsoft.com", "w3.org", "kasperskycontenthub.com", "kaspersky.com", "welivesecurity.com", "google.com", "securelist.com", "securelist.lat", "securelist.ru", "zscaler.com", "orbisius.com", "facebook.com", "yahoo.com", "7-zip.org", "googletagmanager.com", "w.org", "github.com", "mitre.org", "schema.org", "openxmlformats.org", "geoffchappell.com"]
whitelistURLs = ["microsoft.com", "w3.org", "kasperskycontenthub.com", "kaspersky.com", "welivesecurity.com", "google.com", "securelist.com", "securelist.lat", "securelist.ru", "zscaler.com", "orbisius.com", "facebook.com", "yahoo.com", "7-zip.org", "googletagmanager.com", "w.org", "mitre.org", "schema.org", "openxmlformats.org", "geoffchappell.com"]

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


def scrapingIOCs(url, IOC_name):
    # GET the html
    r = requests.get(url)

    # Filter defang
    defangaded = r.text.replace("[.]", ".").replace("hxxp", "http")
    splited = re.split(';|,|<|>| |\n', defangaded)

    # IPS
    ips = re.findall(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", defangaded)
    ips = list(set(ips))
    parent_path = "C:/Users/" + os.getlogin() + "/Downloads/"
    path = os.path.join(parent_path, IOC_name)
    try:
        os.mkdir(path)
        print("[+] Directory '% s' created" % path)
    except OSError as error: 
        print(error)

    with open(path + '/IPs.txt', 'w') as f:
        for ip in ips:
            f.write(ip)
            f.write("\n")

    # DOMAINS
    # otra opcion es con la libreria validators
    def validaDomain(w):
        if re.match(r"^[A-Za-zÀ-ú\.0-9\-]{5,}$", w) and "." in w and w[0] != "." and w[1] != "." and w[-2] != "." and w[-1] != ".":
            d = w.split(".")
            if tld.is_tld(d[-1]):
                return w
        else:
            return False

    domains = []
    for v in splited:
        vv = re.split(':|/', v)
        for w in vv:
            if validaDomain(w):
                domains.append(w)

    domains = list(set(domains))

    def whitelisting(list):
        result = []
        
        for d in list:
            if len(d.split(".")) == 2:
                if d not in whitelistDomains:
                    result.append(d)
            else:
                dd = d.split(".")
                if dd[-2] + "." + dd[-1] not in whitelistDomains:
                    result.append(d)
        return result
    
    with open(path + '/domains.txt', 'w') as f:
        for dom in whitelisting(domains):
            f.write(dom)
            f.write("\n")
    
    # HASHES

    def findHashes(text):
        hashes = {}
        hashes['sha256'] = re.findall(r"\b[A-Fa-f0-9]{64}\b", text)
        hashes['sha1'] = re.findall(r"\b[A-Fa-f0-9]{40}\b", text)
        hashes['md5'] = re.findall(r"\b[A-Fa-f0-9]{32}\b", text)
        hashes['sha256'] = list(set(hashes['sha256']))
        hashes['sha1'] = list(set(hashes['sha1']))
        hashes['md5'] = list(set(hashes['md5']))
        return hashes

    with open(path + '/hashes.txt', 'w') as f:
        for md5 in findHashes(defangaded)['md5']:
            f.write(md5)
            f.write("\n")
        for sha1 in findHashes(defangaded)['sha1']:
            f.write(sha1)
            f.write("\n")
        for sha256 in findHashes(defangaded)['sha256']:
            f.write(sha256)
            f.write("\n")

    #URLs
    def findURLs(text):
        urls = re.findall("https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)", text)
        urls = list(set(urls))
        #Whitelisting:
        result = []
        
        for u in urls:
            t = urlparse(u).netloc
            t = '.'.join(t.split('.')[-2:])
            if t not in whitelistURLs:
                result.append(u)
        
        return result

    with open(path + '/urls.txt', 'w') as f:
        for l in findURLs(defangaded):
            f.write(l)
            f.write("\n")

    


#IOCparser API -> GET request and call createLists
def scrapingIOCsPARSER(urli, IOC_name):
    import requests
    import os

    url = "https://api.iocparser.com/url"

    payload = {"url": urli}
    headers = {
    'Content-Type': 'application/json'
    }

    # Para crear las listas de domains, urls, ips, hashes
    def createLists(name, response):
        parent_path = "C:/Users/" + os.getlogin() + "/Downloads/"
        path = os.path.join(parent_path, name)
        try:
            os.mkdir(path)
            print("[+] Directory '% s' created" % path)
        except OSError as error: 
            print(error)

        with open(path + '/IPs.txt', 'w') as f:
            for l in response.json()['data']['IPv4']:
                f.write(l)
                f.write("\n")

        with open(path + '/domains.txt', 'w') as f:
            for l in response.json()['data']['DOMAIN']:
                f.write(l)
                f.write("\n")
        
        with open(path + '/urls.txt', 'w') as f:
            for l in response.json()['data']['URL']:
                f.write(l)
                f.write("\n")

        with open(path + '/hashes.txt', 'w') as f:
            for l in response.json()['data']['FILE_HASH_MD5']:
                f.write(l)
                f.write("\n")
            for l in response.json()['data']['FILE_HASH_SHA1']:
                f.write(l)
                f.write("\n")
            for l in response.json()['data']['FILE_HASH_SHA256']:
                f.write(l)
                f.write("\n")
            


    # Access the report
    response = requests.request("POST", url, headers=headers, json=payload)
    if response.json()['status'] == "success":
        createLists(IOC_name, response)
    else:
        print("No se puede acceder al report")

# Creacion de .ioc
def createIOC(name):
    description = "-"
    path = "C:/Users/" + os.getlogin() + "/Downloads/" + name + "/"

    #Crea el .ioc de dominios y Urls
    path_domains = os.path.join(path, "domains.txt")
    path_urls = os.path.join(path, "urls.txt")
    if os.path.getsize(path_domains) > 0 or os.path.getsize(path_urls) > 0:
        with open(path + name + ' domains.ioc', 'w') as f:
            f.write("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<ioc xmlns=\"http://schemas.mandiant.com/2010/ioc\">\n    <short_description>" + name + "</short_description>\n" + "    <description>" + description + "</description>\n    <authored_date xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:nil=\"true\"/>\n    <definition>\n        <Indicator operator=\"OR\">\n")
            with open(path_domains, 'r') as domains:
                lines = domains.readlines()
                for d in lines:
                    f.write("            <IndicatorItem condition=\"contains\">\n                <Context document=\"DnsEntryItem\" search=\"DnsEntryItem/RecordName\" type=\"mir\"/>\n                <Content type=\"string\">")
                    f.write(d.strip())
                    f.write("</Content>\n            </IndicatorItem>\n")

            with open(path_urls, 'r') as urls:
                lines = urls.readlines()
                for u in lines:
                    f.write("            <IndicatorItem condition=\"contains\">\n                <Context document=\"UrlHistoryItem\" search=\"UrlHistoryItem/URL\" type=\"mir\"/>\n                <Content type=\"string\">")
                    f.write(u.strip())
                    f.write("</Content>\n            </IndicatorItem>\n")

            f.write("        </Indicator>\n    </definition>\n</ioc>")

    # Crea el .ioc de hashes
    path_hashes = os.path.join(path, "hashes.txt")
    if os.path.getsize(path_hashes) > 0:
        with open(path + name + ' hashes.ioc', 'w') as f:
            f.write("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<ioc xmlns=\"http://schemas.mandiant.com/2010/ioc\">\n    <short_description>" + name + "</short_description>\n" + "    <description>" + description + "</description>\n    <authored_date xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:nil=\"true\"/>\n    <definition>\n        <Indicator operator=\"OR\">\n")
            with open(path_hashes, 'r') as hashes:
                lines = hashes.readlines()
                for h in lines:
                    f.write("            <IndicatorItem condition=\"is\">\n                <Context document=\"FileItem\" search=\"FileItem/Sha1sum\" type=\"mir\"/>\n                <Content type=\"string\">")
                    f.write(h.strip())
                    f.write("</Content>\n            </IndicatorItem>\n")
            f.write("        </Indicator>\n    </definition>\n</ioc>")

    # Crea el .ioc de IPsv4
    path_ips = os.path.join(path, "IPs.txt")
    if os.path.getsize(path_ips) > 0:
        with open(path + name + ' ips.ioc', 'w') as f:
            f.write("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<ioc xmlns=\"http://schemas.mandiant.com/2010/ioc\">\n    <short_description>" + name + "</short_description>\n" + "    <description>" + description + "</description>\n    <authored_date xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:nil=\"true\"/>\n    <definition>\n        <Indicator operator=\"OR\">\n")
            with open(path_ips, 'r') as ips:
                lines = ips.readlines()
                for ip in lines:
                    f.write("            <IndicatorItem condition=\"is\">\n                <Context document=\"FileItem\" search=\"FileItem/Sha1sum\" type=\"mir\"/>\n                <Content type=\"string\">")
                    f.write(ip.strip())
                    f.write("</Content>\n            </IndicatorItem>\n")
            f.write("        </Indicator>\n    </definition>\n</ioc>")




# Create the parser
my_parser = argparse.ArgumentParser(prog = 'IOCollector',
                                    #usage = '%(prog)s [options] URL/IOC_name',
                                    description = 'Specify the URL of a report to gather IOCs and create .ioc files with the OpenIOC format.\nYou can also use the IOCParser API from https://iocparser.com/',
                                    epilog = 'IOC Generator 0.3 Version')

my_parser.version = 'IOC Generator 0.3 Version'
my_parser.add_argument('-v',
                       '--version',
                       action='version',
                       help='display current version')

# For exclusivity
my_group = my_parser.add_mutually_exclusive_group(required=True)

# Arguments
my_group.add_argument('-u',
                       metavar='url',
                       type=str,
                       help='the URL of a report',
                       action='store',
                       nargs=1)

my_parser.add_argument('-i',
                       metavar='IOC_name',
                       type=str,
                       help='the name of your IOC',
                       action='store',
                       nargs=1)

my_group.add_argument('-c',
                       metavar='IOC_name',
                       type=str,
                       help='specify the name for the .ioc (CARMEN)',
                       action='store',
                       nargs=1)

my_parser.add_argument('-p',
                       help='Use the IOCParser API (by default it uses a custom scraping function)',
                       action='store_true')

my_parser.add_argument('-d',
                       help='Show parsed html for debugging purposes.',
                       action='store_true')


# Execute the parse_args() method
args = my_parser.parse_args()

# Execute tool
if args.c:
    createIOC(args.c[0])
    #print(args.c[0])
elif args.u:
    if args.i:
        if args.p:
            print("[+] Scraping with IOCParser API")
            scrapingIOCsPARSER(args.u[0], args.i[0])
        else:
            print("[+] Scraping with custom API")
            scrapingIOCs(args.u[0], args.i[0])
    elif args.d:
        debugging(args.u[0])
    else:
        print("[x] Specify the name for the IOC folder")
        sys.exit()
else:
    print("algo va mal")

