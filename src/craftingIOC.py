# craftingIOC.py
import os

# Creation of .ioc files (OpenIOC format)
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
