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
* Modularity
* Update white list of domains. Implement an option (as argument) to select a custom white list
* Print text for clarity of actions taken, such as creating files
* Clean IOCs: Sometimes it includes legit IPs and strings that look like hashes but they aren't
* Extend support for pdf files and other formats / Extend support for platforms such as Twitter or private sources
* 1 more option (as argument) to concatenate both procceses (scraping and creating the .ioc files)
* 1 more option (as argument) to specify path/folder to save written files
* Web Crawling: Automate the scraping of new reports from main vendors

## Ideas
* Gather TTPs used by APTs
* Threat modeling (types of organizations targeted by groups)

## Changelog
### 0.3 - 2022-09-13
#### Added
* Support for URL gathering
* Minimal whitelisting for default scraping
