# IOCollector

A tool to facilitate gathering IOCs from reports/blogs/documents and creating .ioc files with the OpenIOC format.

## Usage
```
python IOCollector.py -h
usage: IOCollector [-h] [-v] [-u url] [-i IOC_name] [-c IOC_name] [-p]
Specify the URL of a report to gather IOCs and create .ioc files with the OpenIOC format. You can also use the IOCParser API from https://iocparser.com/


options:
-h, --help     show this help message and exit
-v, --version  display current version
-u url         the URL of a report
-i IOC_name    the name of your IOC
-p             Use the IOCParser API (by default it uses a custom scraping function)
-c IOC_name    specify the name to create an .ioc file (OpenIOC format)

```


## To-Do
* Implement URLs for the custom API
* White list of domains and filter them
* Clean IOCs: Sometimes it includes legit IPs and strings that look like hashes but they aren't
* Gather IOCs from pdf files (and other formats)
* 1 more option to concatenate both procceses (scraping and creating the .ioc files)
* Automate the scraping of new reports from main vendors

## Ideas
* Gather TTPs used by APTs
* Threat modeling (types of organizations targeted by groups)

## Changelog
### 0.3 - 2022-09-13
#### Added
* Support for URL gathering
* Minimal whitelisting for default scraping
