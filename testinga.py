import requests
import os
import re
import validators
import tld

url = "https://securelist.com/vilerat-deathstalkers-continuous-strike/107075/"
url = "https://securelist.com/kimsukys-golddragon-cluster-and-its-c2-operations/107258/"
url = "https://unit42.paloaltonetworks.com/cloaked-ursa-online-storage-services-campaigns/"

# GET the html
r = requests.get(url)

# Filter defang
defangaded = r.text.replace("[.]", ".").replace("hxxp", "http")

splited = re.split(';|,|<|>| |\n', defangaded)





# IPS
#ips = re.findall(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", defangaded)
#ips = list(set(ips))



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
print(domains)
print(len(domains))

def whitelisting(list):
    result = []
    whitelist = ["azueracademy.com", "rombaic.com", "openxmlformats.org", "kaspersky.com", "google.com"]
    for d in list:
        if len(d.split(".")) == 2:
            if d not in whitelist:
                result.append(d)
        else:
            dd = d.split(".")
            if dd[-2] + "." + dd[-1] not in whitelist:
                result.append(d)
    return result

print(len(whitelisting(domains)))


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


print((findHashes(defangaded)['sha256']))

#-----------------------------------------------------------------------------------------------------------------
