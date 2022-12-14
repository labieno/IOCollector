# scraperIOC.py
import requests
import re
import os
import sys
import validators
import tld
from urllib.parse import urlparse

# To be upgraded
## whitelistDomains will whitelist the domains and whitelistURLs will whitelist domains and ULRs
whitelistDomains = ["github.com", "twitter.com", "mega.io"]
whitelistURLs = ["pypi.org", "reddit.com", "linkedin.com", "sentinelone.com", "facebook.net", "onesignal.com", "typography.com", "googleoptimize.com", "licdn.com", "smush.cdn", "tvsquared.com", "gravatar.com", "microsoft.com", "wordpress.org", "jsdelivr.net", "hausec.com", "proofpoint.com", "jquery.com", "themespiral.com", "cloudflareinsights.com", "googleapis.com", "thedfirreport.com", "fraunhofer.de", "wp.com", "gmpg.org", "stealthbits.com", "patreon.com", "w3.org", "kasperskycontenthub.com", "kaspersky.com", "welivesecurity.com", "google.com", "securelist.com", "securelist.lat", "securelist.ru", "zscaler.com", "orbisius.com", "facebook.com", "yahoo.com", "7-zip.org", "googletagmanager.com", "w.org", "mitre.org", "schema.org", "openxmlformats.org", "geoffchappell.com", "malwarebytes.com"]

def scrapingIOCs(url, IOC_name):
    # GET the html
    r = requests.get(url)

    # Filter defang (could be done with a dictionary, don't know if it's faster)
    defangaded = r.text.replace("[.]", ".").replace("hxxp", "http").replace("[:]", ":").replace("[://]", "://")
    splited = re.split(';|,|<|>| |\n', defangaded)

    # Setting workspace:
    parent_path = "C:\\Users\\" + os.getlogin() + "\\Downloads\\"
    path = os.path.join(parent_path, IOC_name)
    try:
        os.mkdir(path)
        print("[+] Directory '% s' created" % path)
    except OSError as error: 
        print(error)
        print("[x] Should delete the directory or choose another name")
        sys.exit()



    # DOMAINS
    pathdomains = os.path.join(path, 'domains.txt')

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
        whitelist = whitelistDomains
        whitelist.extend(whitelistURLs)
        for d in list:
            if len(d.split(".")) == 2:
                if d.lower() not in whitelist:
                    result.append(d)
            else:
                dd = d.split(".")
                if (dd[-2] + "." + dd[-1]).lower() not in whitelist:
                    result.append(d)
        return result
    
    if len(whitelisting(domains)) > 0:
        with open(pathdomains, 'w') as f:
            for dom in whitelisting(domains):
                f.write(dom)
                f.write("\n")
        print("     [+] File '% s' created" % pathdomains)


    # HASHES
    pathhashes = os.path.join(path, 'hashes.txt')

    def findHashes(text):
        hashes = {}
        hashes['sha256'] = re.findall(r"\b[A-Fa-f0-9]{64}\b", text)
        hashes['sha1'] = re.findall(r"\b[A-Fa-f0-9]{40}\b", text)
        hashes['md5'] = re.findall(r"\b[A-Fa-f0-9]{32}\b", text)
        hashes['sha256'] = list(set(hashes['sha256']))
        hashes['sha1'] = list(set(hashes['sha1']))
        hashes['md5'] = list(set(hashes['md5']))
        return hashes

    if len(findHashes(defangaded)['sha256']) > 0 or len(findHashes(defangaded)['sha1']) > 0 or len(findHashes(defangaded)['md5']) > 0:
        with open(pathhashes, 'w') as f:
            for md5 in findHashes(defangaded)['md5']:
                f.write(md5)
                f.write("\n")
            for sha1 in findHashes(defangaded)['sha1']:
                f.write(sha1)
                f.write("\n")
            for sha256 in findHashes(defangaded)['sha256']:
                f.write(sha256)
                f.write("\n")
        print("     [+] File '% s' created" % pathhashes)

    #URLs
    pathurls = os.path.join(path, 'urls.txt')

    def findURLs(text):
        urls = re.findall("https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)", text)
        #urls2 = re.findall(r"https?://(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)", text)
        #urls.extend(urls2)
        urls = list(set(urls))
        return urls

    def whitelistingURLs(urls):
        legits = []
        malicious = []
        #result = [legits, malicious]


        # MODO EXIGENTE (se debe cambiar)
        whitelist = whitelistDomains
        whitelist.extend(whitelistURLs)

        
        for u in urls:
            d = urlparse(u).hostname
            if len(d.split(".")) == 2:
                if d not in whitelist:
                    malicious.append(u)
                else:
                    legits.append(u)
            else:
                dd = d.split(".")
                if dd[-2] + "." + dd[-1] not in whitelist:
                    malicious.append(u)
                else:
                    legits.append(u)
    
        return [list(set(legits)), list(set(malicious))]

    # LEGITS URLs (for testing)
    pathurls0 = os.path.join(path, 'urls0.txt')
    with open(pathurls0, 'w') as f:
        for l in whitelistingURLs(findURLs(defangaded))[0]:
            f.write(l)
            f.write("\n")
    
    if len(whitelistingURLs(findURLs(defangaded))[1]) > 0:
        with open(pathurls, 'w') as f:
            for l in whitelistingURLs(findURLs(defangaded))[1]:
                f.write(l)
                f.write("\n")
        print("     [+] File '% s' created" % pathurls)

    
    # IPS
    pathips = os.path.join(path, 'ips.txt')

    ips = re.findall(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", defangaded)
    ips = list(set(ips))

    wips = []
    # Whitelisting IPs: searching for IPs in legit URLs
    for ip in ips:
        # if ip is in legit URL
        t = 0
        for legitUrl in whitelistingURLs(findURLs(defangaded))[0]:
            if ip in legitUrl:
                t = 1
                break
        if t == 0:
            wips.append(ip)
        
    if len(wips) > 0:
        with open(pathips, 'w') as f:
            for ip in wips:
                f.write(ip)
                f.write("\n")
        print("     [+] File '% s' created" % pathips)


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

        # Setting workspace
        parent_path = "C:\\Users\\" + os.getlogin() + "\\Downloads\\"
        path = os.path.join(parent_path, name)
        try:
            os.mkdir(path)
            print("[+] Directory '% s' created" % path)
        except OSError as error: 
            print(error)
            print("[x] Should delete the directory or choose another name")
            sys.exit()

        # IPs
        pathips = os.path.join(path, 'ips.txt')

        if len(response.json()['data']['IPv4']) > 0:
            with open(pathips, 'w') as f:
                for l in response.json()['data']['IPv4']:
                    f.write(l)
                    f.write("\n")
            print("     [+] File '% s' created" % pathips)


        # Domains
        pathdomains = os.path.join(path, 'domains.txt')

        if len(response.json()['data']['DOMAIN']) > 0:
            with open(pathdomains, 'w') as f:
                for l in response.json()['data']['DOMAIN']:
                    f.write(l)
                    f.write("\n")
            print("     [+] File '% s' created" % pathdomains)
        

        # Urls
        pathurls = os.path.join(path, 'urls.txt')

        if len(response.json()['data']['URL']) > 0:
            with open(pathurls, 'w') as f:
                for l in response.json()['data']['URL']:
                    f.write(l)
                    f.write("\n")
            print("     [+] File '% s' created" % pathurls)


        # Hashes
        pathhashes = os.path.join(path, 'hashes.txt')

        if len(response.json()['data']['FILE_HASH_MD5']) > 0 or len(response.json()['data']['FILE_HASH_SHA1']) > 0 or len(response.json()['data']['FILE_HASH_SHA256']) > 0:
            with open(pathhashes, 'w') as f:
                for l in response.json()['data']['FILE_HASH_MD5']:
                    f.write(l)
                    f.write("\n")
                for l in response.json()['data']['FILE_HASH_SHA1']:
                    f.write(l)
                    f.write("\n")
                for l in response.json()['data']['FILE_HASH_SHA256']:
                    f.write(l)
                    f.write("\n")
            print("     [+] File '% s' created" % pathhashes)
            

    # Access the report
    response = requests.request("POST", url, headers=headers, json=payload)
    if response.json()['status'] == "success":
        createLists(IOC_name, response)
    else:
        print("No se puede acceder al report")

