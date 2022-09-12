# IOCgen.py
import argparse
import os
import sys
import requests

def scrapingIOCs(urli, IOC_name):
    import requests
    import os

    url = "https://api.iocparser.com/url"

    payload = {"url": urli}
    headers = {
    'Content-Type': 'application/json'
    }


    def createLists(name, response):
        parent_path = "C:/Users/" + os.getlogin() + "/Downloads/"
        path = os.path.join(parent_path, name)
        try:
            os.mkdir(path)
            print("Directory '% s' created" % path)
        except OSError as error: 
            print(error)

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
            
        with open(path + '/IPs.txt', 'w') as f:
            for l in response.json()['data']['IPv4']:
                f.write(l)
                f.write("\n")


    response = requests.request("POST", url, headers=headers, json=payload)
    if response.json()['status'] == "success":
        createLists(IOC_name, response)

    else:
        print("No se puede acceder al report")

def createIOC(IOC_name):
    description = "-"

    def createIOCfiles(name):
        path = "C:/Users/" + os.getlogin() + "/Downloads/" + name + "/"

        #Crea el .ioc de dominios y Urls
        path_domains = os.path.join(path, "domains.txt")
        path_urls = os.path.join(path, "urls.txt")
        if os.path.getsize(path_domains) > 0 or os.path.getsize(path_urls) > 0:
            with open(path + name + ' domains.ioc', 'w') as f:
                f.write("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<ioc xmlns=\"http://schemas.mandiant.com/2010/ioc\">\n    <short_description>" + IOC_name + "</short_description>\n" + "    <description>" + description + "</description>\n    <authored_date xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:nil=\"true\"/>\n    <definition>\n        <Indicator operator=\"OR\">\n")
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
                f.write("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<ioc xmlns=\"http://schemas.mandiant.com/2010/ioc\">\n    <short_description>" + IOC_name + "</short_description>\n" + "    <description>" + description + "</description>\n    <authored_date xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:nil=\"true\"/>\n    <definition>\n        <Indicator operator=\"OR\">\n")
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
                f.write("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<ioc xmlns=\"http://schemas.mandiant.com/2010/ioc\">\n    <short_description>" + IOC_name + "</short_description>\n" + "    <description>" + description + "</description>\n    <authored_date xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:nil=\"true\"/>\n    <definition>\n        <Indicator operator=\"OR\">\n")
                with open(path_ips, 'r') as ips:
                    lines = ips.readlines()
                    for ip in lines:
                        f.write("            <IndicatorItem condition=\"is\">\n                <Context document=\"FileItem\" search=\"FileItem/Sha1sum\" type=\"mir\"/>\n                <Content type=\"string\">")
                        f.write(ip.strip())
                        f.write("</Content>\n            </IndicatorItem>\n")
                f.write("        </Indicator>\n    </definition>\n</ioc>")

    createIOCfiles(IOC_name)


# Create the parser
my_parser = argparse.ArgumentParser(prog = 'IOCgen',
                                    #usage = '%(prog)s [options] URL/IOC_name',
                                    description = 'Specify the URL of a report, or name your IOC',
                                    epilog = 'IOC Generator')

my_parser.version = 'IOC Generator 0.1 version'
my_parser.add_argument('-v',
                       '--version',
                       action='version',
                       help='display current version')

#my_group = my_parser.add_mutually_exclusive_group(required=True)

# Arguments
my_parser.add_argument('-u',
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

my_parser.add_argument('-c',
                       metavar='IOC_name',
                       type=str,
                       help='specify the name for the .ioc (CARMEN)',
                       action='store',
                       nargs=1)


# Execute the parse_args() method
args = my_parser.parse_args()


if args.c:
    createIOC(args.c[0])
    #print(args.c[0])


elif args.u:
    if args.i:
        scrapingIOCs(args.u[0], args.i[0])
    else:
        print("Specify a name for the IOC folder")
else:
    print("algo va mal")



""" input_tool = args.Tool
tools_available = ["parser"]

if input_tool not in tools_available:
    print('The tool specified does not exist')
    print('Choose one of the followings:')
    print('     parser')
    sys.exit()

# Execute tool
print("Se ha escogido " + input_tool) """
