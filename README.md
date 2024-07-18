# Virustotal URL and File Scanner

This script allows you to scan URLs and files for potential threats using the VirusTotal API. It can also generate a PDF report of the scan results and request rescans for URLs.

## Prerequisites


1. **API Key:** You need a free VirusTotal API key.  
   * Get one from [VirusTotal](https://www.virustotal.com) - 500 free lookups per day.
2. **Brew:** Install brew if you don't already have it to install the tools required:
   ````
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ````
3. **jq:** This tool is required for parsing JSON responses:
    ```sh
    brew install jq
    ```
4. **curl:** For making HTTP requests:
    ```sh
    brew install curl
    ```
5. **coreutils:** Provides `shasum` for generating SHA-256 hash values:
   ```
   brew install coreutils
   ```
## Usage
```
Usage: ./scanner.sh [-a api_key] [-u url] [-f file] [-p] [-r] [-h]
  -a: (Required) Set the API key for VirusTotal.
  -u: (Required for URL scan) Set the URL to be scanned.
  -f: (Required for file scan) Set the file to be scanned.
  -p: Generate a PDF report of the scan results.
  -r: Rescan the URL.
  -h: Display this help message.
```


1. **Clone the repository or download the script:**
   You can clone this script from the repository using Git or simply download the single script file to your local machine.

```
git clone git@github.com:padilladan/virustotalURLscanner.git
```

2. **cd into the directory and run the following command to make the script executable:** 
```
chmod +x scanner.sh
```

3. **Sample of script use:**
```
./scanner.sh -a 123f456a789k012e -u https://www.espn.com -p
```
This sample command scans the ESPN url and, with the -p flag, saves the report as a pdf on the desktop