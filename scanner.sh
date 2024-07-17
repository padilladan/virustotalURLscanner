#!/bin/bash

# Variables
api=""
url=""
output_file=""  # Output PDF file path
generate_pdf=false
rescan=false

# This will process the flags used with the command
while getopts "a:u:pr" opt; do
  case $opt in
    a) api="$OPTARG" ;;  # Set API key
    u) url="$OPTARG" ;;  # Set URL
    p) generate_pdf=true ;;  # Flag to generate PDF
    r) rescan=true ;;  # Flag to rescan the URL
    \?) echo "Usage: cmd [-a api_key] [-u url] [-p] [-r]" >&2
        exit 1
        ;;
  esac
done

# Check if the flags are provided
if [[ -z "$api" || -z "$url" ]]; then
  echo "Both API key and URL must be provided."
  echo "Usage: $0 -a api_key -u url [-p] [-r]"
  exit 1
fi

# Extract domain name, remove protocol, "www.", and ".com"
domain=$(echo "$url" | awk -F[/:] '{print $4}' | sed 's/^www\.//;s/\.com$//')
output_file="$HOME/Desktop/${domain}_report.pdf"

# Check if the file already exists, and if so, add a timestamp
if [ -f "$output_file" ]; then
  timestamp=$(date +"%Y%m%d_%H%M%S")
  output_file="$HOME/Desktop/${domain}_report_$timestamp.pdf"
fi

# Initial scan POST request
initial_scan_response=$(curl --silent --request POST \
  --url https://www.virustotal.com/api/v3/urls \
  --form "url=$url" \
  --header "x-apikey: $api")

# Debugging: Print the full initial scan response
echo "Initial scan response:"
echo "$initial_scan_response" | jq .

# Extract the URL ID from the initial scan POST response
url_id=$(echo "$initial_scan_response" | jq -r '.data.id' | sed 's/^u-//')

# Check if URL ID is not empty
if [ -z "$url_id" ]; then
  echo "Failed to create the report on VirusTotal API"
  exit 1
fi

# Variable to store the analysis ID
analysis_id=""

# If rescan flag is set, confirm with the user
if [ "$rescan" = true ]; then
  echo "Are you sure you want to rescan the URL? (y/n)"
  read confirmation
  if [[ "$confirmation" =~ ^[Yy]$ ]]; then
    echo "Re-scanning...may take a few minutes"

    # Debugging: print URL ID
    echo "Using URL ID for rescan: $url_id"

    # Rescan POST request
    rescan_response=$(curl --silent --request POST \
      --url "https://www.virustotal.com/api/v3/urls/${url_id}/analyse" \
      --header "x-apikey: $api")

    echo "Rescan initiated for URL: $url"

    # Troubleshooting step to print the full rescan response
    echo "Full rescan response:"
    echo "$rescan_response" | jq .

    # Extract the new analysis ID from the rescan response
    analysis_id=$(echo "$rescan_response" | jq -r '.data.id')

    # Troubleshooting step to print the extracted ID
    echo "Extracted analysis ID from rescan response: $analysis_id"

    # Check if the new analysis ID is not empty
    if [ -z "$analysis_id" ]; then
      echo "Failed to initiate rescan"
      exit 1
    fi
  fi
fi

# If no rescan or user declined rescan, use the initial analysis ID
if [ -z "$analysis_id" ]; then
  # Extract the analysis ID from the initial POST response
  analysis_id=$(echo "$initial_scan_response" | jq -r '.data.id')
fi

# Run curl and save the result to a temporary file using the analysis ID from the rescan response
response=$(curl --silent --request GET --url "https://www.virustotal.com/api/v3/analyses/$analysis_id" --header "x-apikey: $api")

# Print the response in JSON format for troubleshooting
echo "GET response:"
echo "$response" | jq .

# Check if response is not empty
if [ -z "$response" ]; then
  echo "No response from VirusTotal API"
  exit 1
fi

# Extract the last_analysis_date or fallback to date if not present
last_analysis_date=$(echo "$response" | jq -r '.data.attributes.last_analysis_date // .data.attributes.date')

# Convert the Unix timestamp to a readable date format using a portable method
if [[ "$last_analysis_date" =~ ^[0-9]+$ ]]; then
  readable_date=$(date -u -d @"$last_analysis_date" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -u -r "$last_analysis_date" '+%Y-%m-%d %H:%M:%S')
else
  readable_date="N/A"
fi

# Print the last_analysis_date
echo "Last scan of site: $readable_date"

# Print the response if the PDF flag is not set
if [ "$generate_pdf" = false ]; then
  echo "$response" | jq .
fi

# Generate PDF if the flag is set
if [ "$generate_pdf" = true ]; then
  # Save the formatted JSON response to a temporary HTML file
  temp_html=$(mktemp /tmp/response.XXXXXX.html)
  echo "<pre>$(echo "$response" | jq .)</pre>" > "$temp_html"

  # Convert HTML to PDF using wkhtmltopdf or pandoc with a specified PDF engine
  if command -v wkhtmltopdf &> /dev/null; then
    wkhtmltopdf "$temp_html" "$output_file"
    echo "PDF report saved to $output_file"
  elif command -v pandoc &> /dev/null; then
    pandoc "$temp_html" --pdf-engine=weasyprint -o "$output_file"
    echo "PDF report saved to $output_file"
  else
    echo "Neither wkhtmltopdf nor pandoc with a PDF engine is installed. Please install one of these tools to generate PDF reports."
  fi

  # Clean up temporary HTML file
  rm "$temp_html"
fi
