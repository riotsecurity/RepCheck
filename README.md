# RepCheck - a reputation checker
This tool is a quick and dirty solution used to quickly perform fast triage for specific targets (IPs, URLs, hosts or domains). The APIs of VirusTotal, AlienVault OTX and AbuseIPDB are used for this purpose.  
The results only provide an initial assessment and not a detailed analysis. However, this can be particularly helpful when there are many objects to be examined in order to obtain a first quick evaluation.

Note:
- The results of VirusTotal only refer to analyses that have already been  
  carried out. No new ones are performed!
- The results of AlienVault OTX only show whether there are already pulses  
  for the object to be examined. No verdict is queried.
- AbuseIPDB can only be used for checking IP addresses.

## Requirements
- python3
- python requests
  (on Ubuntu use `sudo apt install python3-requests-futures` for installation)
- python-dotenv (install with `pip install python-dotenv`)
- API key for VirusTotal (free)
- API key for AlienVault OTX (free)
- API key for AbuseIPDB (free, optional)

## Usage
First of all you need to configure your API keys:
1. Create a `.env` file in the same directory as the script:
   ```bash
   cp .env.example .env
   ```

2. Edit the `.env` file with your API keys:
   ```bash
   vim .env
   ```

3. Add your API keys to the file:
   ```
   # VirusTotal API Key
   VT_API=abcdef1234567890

   # AlienVault OTX API Key
   OTX_API=1234567890abcdef

   # AbuseIPDB API Key
   ABUSEIP_API=oiuzt567890123
   ```

You have the following options for running the program:
```
  -h, --help
  -i ioc      Scan for a single IP, URL, host or domain
  -I file     Provide a file with multiple IPs, URLs, hosts or domains
  -u          Printing only "unclean" results for better clarity
  -b          Remove the banner output. Useful for use within scripts.
```

The following example shows the output of the program when loading a file with several entries:
![repcheck_output](/images/output.png)


## Author and License
Author: Timo Sablowski  
License: GNU GPLv3
