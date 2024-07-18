# Virustotal URL and File Scanner

This script allows you to scan URLs and files for potential threats using the VirusTotal API. It can also generate a PDF report of the scan results and request rescans for URLs.

1. ### Security-focused
   * **Real-time Updates:** Frequent malware signature updates.
   * **Community Contributions:** Public votes and comments on content safety.
   * **Premium Sharing:** Advanced analysis for premium users.

2. ### Many Contributors
   * **Diverse Sources:** Data from multiple antivirus engines and scanners.
   * **Comprehensive Coverage:** Heuristic engines, bad signatures, metadata extraction.

3. ### Free and Unbiased
   * **Free Service:** Available for non-commercial use.
   * **Aggregator Role:** Unbiased results from various organizations.

4. ### Community and Sharing
   * **Public Sharing:** Community comments and votes enhance understanding.
   * **Premium Services:** Tools for advanced threat discovery and analysis.

5. ### Detailed Results
   * **Detection Labels:** Specific threat information from each engine.
   * **URL Scanners:** Differentiates between malware, phishing, and suspicious sites.

## Prerequisites


1. **API Key:** You need a free VirusTotal API key.  
   * Get one from [VirusTotal](https://www.virustotal.com) - 500 free lookups per day.
2. **Brew:** Install brew if you don't already have it to install the tools required:
   ````
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ````
3. **Tools Used:** Make sure to download all the tools necessary for the script to function:
   ```sh
   brew install jq
   brew install curl
   brew install perl
   brew install coreutils
   ```
   * **jq:** A lightweight and flexible command-line JSON processor. 
   * **curl:** A command-line tool for transferring data with URLs. 
   * **perl:** Converts UNIX timestamps into human-readable dates. 
   * **base64:** For encoding and decoding base64. 
   * **coreutils:** For the stat command used in the script.


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
cd virustotalURLscanner
chmod +x scanner.sh

```

3. **Sample of script use:**
```
./scanner.sh -a 123f456a789k012e -u https://www.espn.com -p
```
This sample command scans the ESPN url and, with the -p flag, saves the report as a pdf on the desktop