# scraperIOC.py
import requests
import re
import os
import validators
import tld
from urllib.parse import urlparse

# To be upgraded
whitelistDomains = ["microsoft.com", "w3.org", "kasperskycontenthub.com", "kaspersky.com", "welivesecurity.com", "google.com", "securelist.com", "securelist.lat", "securelist.ru", "zscaler.com", "orbisius.com", "facebook.com", "yahoo.com", "7-zip.org", "googletagmanager.com", "w.org", "github.com", "mitre.org", "schema.org", "openxmlformats.org", "geoffchappell.com"]
whitelistURLs = ["microsoft.com", "w3.org", "kasperskycontenthub.com", "kaspersky.com", "welivesecurity.com", "google.com", "securelist.com", "securelist.lat", "securelist.ru", "zscaler.com", "orbisius.com", "facebook.com", "yahoo.com", "7-zip.org", "googletagmanager.com", "w.org", "mitre.org", "schema.org", "openxmlformats.org", "geoffchappell.com"]

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

