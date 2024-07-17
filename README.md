# Virustotal URL Scanner

This script provides a way to make GET requests to the VirusTotal API to retrieve information about URLs via terminal. It uses your API key, from the virustotal.com site, and URL as flags.

## Prerequisites


1. **API Key:** You need a VirusTotal API key.  
   Get one from [VirusTotal](https://www.virustotal.com).
2. **jq:** This tool is required for parsing JSON responses. You can install it using:
    ```sh
    sudo apt-get install jq  # For Debian/Ubuntu
    sudo yum install jq      # For CentOS/RHEL
    brew install jq          # For macOS
    ```
3. **PDF Generation Tools:** To generate PDF reports, either `wkhtmltopdf` or `pandoc` with a PDF engine (like `weasyprint`) should be installed. You can install them using:
    ```sh
    sudo apt-get install wkhtmltopdf  # For Debian/Ubuntu
    sudo yum install wkhtmltopdf      # For CentOS/RHEL
    brew install wkhtmltopdf          # For macOS

    sudo apt-get install pandoc weasyprint  # For Debian/Ubuntu
    sudo yum install pandoc weasyprint      # For CentOS/RHEL
    brew install pandoc weasyprint          # For macOS
    ```

## Usage

```sh
./script.sh -a <api_key> -u <url> [-p]

## Installation and Use

1. **Clone the repository or download the script:**
   You can clone this script from the repository using Git or simply download the single script file to your local machine.

```
git clone https://your-repository-url-here
```

2. **Run the following command to make the script executable:** 
```
chmod +x scanner.sh
```

3. **Sample of script use:**
```
./scanner.sh -a "abcd1234" -u "http://example.com"
```