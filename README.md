# IOCollector

A tool to facilite gathering IOCs from reports/blogs/documents and creating .ioc files with the OpenIOC format.

## Usage
python IOCollector.py -h
usage: IOCollector [-h] [-v] [-u url] [-i IOC_name] [-c IOC_name] [-p]
Specify the URL of a report to gather IOCs and create .ioc files with the OpenIOC format. You can also use the IOCParser API from https://iocparser.com/                                                                                                                                                                                           options:
-h, --help     show this help message and exit
-v, --version  display current version
-u url         the URL of a report
-i IOC_name    the name of your IOC
-p             Use the IOCParser API (by default it uses a custom API)
-c IOC_name    specify the name to create an .ioc file (OpenIOC format)
