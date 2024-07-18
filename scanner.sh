#!/bin/bash

# Function to display the help message
show_help() {
    cat << EOF
Usage: ./scanner.sh [-a api_key] [-u url] [-f file] [-p] [-r] [-h]
  -a: (Required) Set the API key for VirusTotal.
  -u: (Required for URL scan) Set the URL to be scanned.
  -f: (Required for file scan) Set the file to be scanned.
  -p: Generate a PDF report of the scan results.
  -r: Rescan the URL.
  -h: Display this help message.
EOF
}

# Function to display an error message
show_error() {
    local message="$1"
    echo "Error: $message"
    exit 1
}

# Function to check for date/time values and print them in human-readable form
check_for_date_time() {
    local command="$1"
    local response="$2"
    local dates=$(echo "$response" | jq -r '.. | .date? // empty')

    [[ -n "$dates" ]] && echo "Command: $command"
    for date in $dates; do
        readable_date=$(date -r "$date" +"%Y-%m-%d %H:%M:%S")
        echo "Date: $readable_date"
    done
}

# Function to submit URL for analysis
submit_url() {
    response=$(curl --silent --request POST --url https://www.virustotal.com/api/v3/urls --form url="$url" --header "x-apikey: $api_key")
    analysis_id=$(echo "$response" | jq -r '.data.id')
    if [[ $analysis_id == null ]]; then
        show_error "Error in URL submission: $response"
    fi
    echo "URL submitted successfully. Analysis ID: $analysis_id"
    check_for_date_time "submit_url" "$response"
}

# Function to check analysis status
check_analysis_status() {
    local status="queued"
    local counter=0

    while [[ "$status" == "queued" && $counter -lt 10 ]]; do
        ((counter++))
        analysis_response=$(curl --silent --request GET --url "https://www.virustotal.com/api/v3/analyses/$analysis_id" --header "x-apikey: $api_key")
        status=$(echo "$analysis_response" | jq -r '.data.attributes.status')
        [[ "$status" == "queued" ]] && sleep 2
    done

    if [[ "$status" == "queued" ]]; then
        show_error "Reached 10 API requests. The analysis is taking longer than expected."
    fi

    [[ "$generate_pdf" == "false" ]] && echo "$analysis_response" | jq '.'
    response="$analysis_response"
    check_for_date_time "check_analysis_status" "$response"
}

# Function to request a URL rescan
request_url_rescan() {
    response=$(curl --silent --request POST --url https://www.virustotal.com/api/v3/urls/"$analysis_id"/analyse --header "x-apikey: $api_key")
    check_for_date_time "request_url_rescan" "$response"

    local status="queued"
    local counter=0

    while [[ "$status" == "queued" && $counter -lt 10 ]]; do
        ((counter++))
        analysis_response=$(curl --silent --request GET --url "https://www.virustotal.com/api/v3/analyses/$analysis_id" --header "x-apikey: $api_key")
        status=$(echo "$analysis_response" | jq -r '.data.attributes.status')
        [[ "$status" == "queued" ]] && sleep 2
    done

    if [[ "$status" == "queued" ]]; then
        show_error "Reached 10 API requests. The analysis is taking longer than expected."
    fi

    [[ "$generate_pdf" == "false" ]] && echo "$analysis_response" | jq '.'
    response="$analysis_response"
    check_for_date_time "request_url_rescan" "$response"
}

# Function to confirm URL rescan
get_url_rescan_confirmation() {
    read -p "Do you want to proceed with the URL rescan? (y/n): " confirm
    [[ "$confirm" == "y" ]] && request_url_rescan && [[ "$generate_pdf" == "true" ]] && save_as_pdf
}

# Function to save the response as a PDF
save_as_pdf() {
    timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
    if [[ -n "$file" ]]; then
        filename=$(basename "$file")
        base_name="${filename%.*}"
    else
        domain=$(echo "$url" | awk -F/ '{print $3}' | sed 's/^www\.//')
        base_name="$domain"
    fi
    json_file=~/Desktop/"${base_name}_${timestamp}_scan_report.json"
    echo "$response" | jq '.' > "$json_file"
    echo "Report saved as $json_file"
}

# Function to upload a file smaller than 32MB
upload_file() {
    response=$(curl --silent --request POST --url https://www.virustotal.com/api/v3/files --header "x-apikey: $api_key" --form file=@"$file")
    analysis_id=$(echo "$response" | jq -r '.data.id')
    if [[ $analysis_id == null ]]; then
        show_error "Error in file upload: $response"
    fi
    echo "File uploaded successfully."
    echo "Analysis ID: $analysis_id"
    check_for_date_time "upload_file" "$response"
}

# Function to get a file report
get_file_report() {
    # Convert the file to SHA-256 hash
    sha256_hash=$(shasum -a 256 "$file" | awk '{print $1}')

    # Use the SHA-256 hash with the curl command
    analysis_response=$(curl --silent --request GET --url "https://www.virustotal.com/api/v3/files/$sha256_hash" --header "accept: application/json" --header "x-apikey: $api_key")

    if [[ $(echo "$analysis_response" | jq -r '.data.id') == null ]]; then
        echo "Error in retrieving file report: $analysis_response"
        echo "Debug Info - API Key: $api_key, SHA-256 Hash: $sha256_hash"
        show_error "Error in retrieving file report: $analysis_response"
    fi

    response="$analysis_response"
    check_for_date_time "get_file_report" "$response"
    if [[ "$generate_pdf" == "true" ]]; then
        save_as_pdf
    else
        echo "$analysis_response" | jq '.'
    fi
}

# Function to get a URL for uploading large files
get_upload_url() {
    response=$(curl --silent --request GET --url https://www.virustotal.com/api/v3/files/upload_url --header "x-apikey: $api_key")
    upload_url=$(echo "$response" | jq -r '.data')
    if [[ $upload_url == null ]]; then
        show_error "Error in getting upload URL: $response"
    fi
    echo "Upload URL obtained: $upload_url"
}

# Function to upload a file larger than 32MB using the obtained upload URL
upload_large_file() {
    response=$(curl --silent --request POST --url "$upload_url" --header "x-apikey: $api_key" --form file=@"$file")
    analysis_id=$(echo "$response" | jq -r '.data.id')
    if [[ $analysis_id == null ]]; then
        show_error "Error in large file upload: $response"
    fi
    echo "Large file uploaded successfully."
    echo "Analysis ID: $analysis_id"
    check_for_date_time "upload_large_file" "$response"
}

# Initialize variables
api_key=""
url=""
file=""
generate_pdf="false"
rescan="false"

# Parse command-line options
while getopts "a:u:f:prh" opt; do
    case $opt in
        a) api_key="$OPTARG" ;;
        u) url="$OPTARG" ;;
        f) file="$OPTARG" ;;
        p) generate_pdf="true" ;;
        r) rescan="true" ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

# Check if the API key is provided
if [[ -z "$api_key" ]]; then
    show_error "API key is required. Use the -a flag to provide it."
fi

# Validate required options
if [[ -z "$url" && -z "$file" ]]; then
    show_error "Either a URL (-u) or a file (-f) must be provided."
fi

# Ensure only one of -u or -f is used
if [[ -n "$url" && -n "$file" ]]; then
    show_error "Use only one of -u or -f at a time."
fi

# Ensure -r is not used with -f
if [[ -n "$file" && "$rescan" == "true" ]]; then
    show_error "A rescan flag(-r) cannot be used when scanning a file - only usable with a URL scan"
fi

# Main workflow
if [[ -n "$file" ]]; then
    # Check if file exists
    if [[ ! -f "$file" ]]; then
        show_error "File not found: $file"
    fi

    # Check file size (corrected for macOS)
    file_size=$(stat -f%z "$file")
    if (( file_size < 32000000 )); then
        upload_file
        get_file_report
    else
        get_upload_url
        upload_large_file
        get_file_report
    fi
elif [[ -n "$url" ]]; then
    submit_url
    check_analysis_status
fi
