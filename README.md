# RepCheck - a reputation checker
This tool is a quick and dirty solution used to quickly perform fast triage for specific targets (IPs, URLs, hosts or domains). The APIs of VirusTotal and AlienVault OTX are used for this purpose.  
The results only provide an initial assessment and not a detailed analysis. However, this can be particularly helpful when there are many objects to be examined in order to obtain a first quick evaluation.

Note:
- The results of VirusTotal only refer to analyses that have already been  
  carried out. No new ones are performed!
- The results of AlienVault OTX only show whether there are already pulses  
  for the object to be examined. No verdict is queried.

## Requirements
- python3
- python requests  
  (on Ubuntu use `sudo apt install python3-requests-futures` for installation)
- API key for VirusTotal (free)
- API key for AlienVault OTX (free)

## Usage
First of all you need to configure your API keys:
- Open the python file with your preferred editor, e.g.
  ```bash
  vim repcheck.py
  ```
- Search for the "CONFIG" section at the top
- Edit the variables to contain your API keys, e.g.
  ```python
  vt_api = "abcdef1234567890"
  otx_api = "1234567890abcdef"
  ```
  ![repcheck_keys](https://github.com/riotsecurity/RepCheck/assets/61002269/1ad93d67-016b-48ad-8de9-be6fc6fc38a6)

You have the following options for running the program:
```
  -h, --help
  -i ioc      Scan for a single IP, URL, host or domain
  -I file     Provide a file with multiple IPs, URLs, hosts or domains
```

The following example shows the output of the program when loading a file with several entries:
![repcheck_output](https://github.com/riotsecurity/RepCheck/assets/61002269/ab54c2fc-dc12-4135-a9f6-9cbaaaa79178)


## Author and License
Author: Timo Sablowski  
License: GNU GPLv3
