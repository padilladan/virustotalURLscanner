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

# Function to display an error message and exit
show_error() {
    echo "Error: $1"
    exit 1
}

# Function to encode the URL to base64 without padding
encode_url() {
    local url="$1"
    echo -n "$url" | base64 | tr -d '=' | tr '/+' '_-'
}

# Function to extract and print the analysis date
print_analysis_date() {
    local response="$1"
    local timestamp=$(echo "$response" | jq -r '.data.attributes.date')
    local human_readable_date=$(perl -e "use POSIX qw(strftime); print strftime('%Y-%m-%d %H:%M:%S', localtime($timestamp));")
    echo "Analysis Date: $human_readable_date"
}

# Function to extract and print the submission and modification dates
print_submission_and_modification_dates() {
    local response="$1"
    local first_submission_timestamp=$(echo "$response" | jq -r '.data.attributes.first_submission_date')
    local submission_timestamp=$(echo "$response" | jq -r '.data.attributes.last_submission_date')
    local modification_timestamp=$(echo "$response" | jq -r '.data.attributes.last_modification_date')

    local human_readable_first_submission_date=$(perl -e "use POSIX qw(strftime); print strftime('%Y-%m-%d %H:%M:%S', localtime($first_submission_timestamp));")
    local human_readable_submission_date=$(perl -e "use POSIX qw(strftime); print strftime('%Y-%m-%d %H:%M:%S', localtime($submission_timestamp));")
    local human_readable_modification_date=$(perl -e "use POSIX qw(strftime); print strftime('%Y-%m-%d %H:%M:%S', localtime($modification_timestamp));")

    echo "First Submission Date: $human_readable_first_submission_date"
    echo "Last Submission Date: $human_readable_submission_date"
    echo "Last Modification Date: $human_readable_modification_date"
}

# Function to save the response as a PDF
save_as_pdf() {
    local response="$1"
    local timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
    local base_name
    if [[ -n "$file" ]]; then
        base_name=$(basename "$file")
        base_name="${base_name%.*}"
    else
        base_name=$(echo "$url" | sed -E 's/^(https?:\/\/)?(www\.)?//')
        base_name="${base_name%/}"
    fi
    local json_file=~/Desktop/"${base_name}_${timestamp}_scan_report.json"
    echo "$response" | jq '.' > "$json_file"
    echo "Report saved as $json_file"
}

# Function to submit URL for analysis
submit_url() {
    response=$(curl --silent --request POST --url https://www.virustotal.com/api/v3/urls --form url="$url" --header "x-apikey: $api_key")
    analysis_id=$(echo "$response" | jq -r '.data.id')
    [[ $analysis_id == null ]] && show_error "Error in URL submission: $response"
    echo "URL submitted successfully" >&2
    echo "$analysis_id"
}

# Function to get URL analysis report
get_url_report() {
    encoded_url=$(encode_url "$url")

    response=$(curl --silent --request GET \
        --url "https://www.virustotal.com/api/v3/urls/$encoded_url" \
        --header "accept: application/json" \
        --header "x-apikey: $api_key")

    [[ $(echo "$response" | jq -r '.data.id') == null ]] && show_error "Error in retrieving URL report: $response"

    if [[ "$generate_pdf" == "true" ]]; then
        save_as_pdf "$response"
    else
        echo "$response" | jq '.'

        # Print the analysis date
        print_submission_and_modification_dates "$response"
    fi
}

# Function to check analysis status
check_analysis_status() {
    local analysis_id="$1"
    local counter=0

    while [[ "$status" != "completed" && $counter -lt 10 ]]; do
        ((counter++))
        response=$(curl --silent --request GET --url "https://www.virustotal.com/api/v3/analyses/$analysis_id" --header "x-apikey: $api_key")
        status=$(echo "$response" | jq -r '.data.attributes.status')
        echo "Requests made: $counter | Status: $status"
        [[ "$status" == "queued" ]] && sleep 2
    done

    if [[ "$status" != "completed" ]]; then
        echo "$response"
        show_error "Analysis did not complete within the expected time."
        echo "$response"
        exit 1
    fi
}


# Function to request a URL rescan with confirmation
request_url_rescan_confirmation() {
    read -p "Do you want to proceed with the URL rescan? (y/n): " confirm
    [[ "$confirm" != "y" ]] && exit 0

    encoded_url=$(encode_url "$url")
    response=$(curl --silent --request POST --url https://www.virustotal.com/api/v3/urls/"$encoded_url"/analyse --header "x-apikey: $api_key")

    # Extract the analysis ID from the response
    analysis_id=$(echo "$response" | jq -r '.data.id')

    # Check if the analysis ID is valid
    [[ $analysis_id == null ]] && show_error "Error in URL rescan request: $response"

    # Get the URL analysis report using the analysis ID
    get_response=$(curl --silent --request GET --url https://www.virustotal.com/api/v3/analyses/"$analysis_id" --header 'accept: application/json' --header "x-apikey: $api_key")

    if [[ "$generate_pdf" == "true" ]]; then
        save_as_pdf "$get_response"
    else
        echo "$get_response" | jq '.'

        # Print the analysis date
        print_analysis_date "$get_response"
    fi
}

# Function to upload a file smaller than 32MB
upload_file() {
    response=$(curl --silent --request POST --url https://www.virustotal.com/api/v3/files --header "x-apikey: $api_key" --form file=@"$file")
    analysis_id=$(echo "$response" | jq -r '.data.id')
    [[ $analysis_id == null ]] && show_error "Error in file upload: $response"
    echo "File uploaded successfully" >&2
#    echo "$analysis_id"
}

# Function to get a file report
get_file_report() {
    local sha256_hash=$(shasum -a 256 "$file" | awk '{print $1}')
    response=$(curl --silent --request GET --url "https://www.virustotal.com/api/v3/files/$sha256_hash" --header "accept: application/json" --header "x-apikey: $api_key")
    [[ $(echo "$response" | jq -r '.data.id') == null ]] && show_error "Error in retrieving file report: $response"
    if [[ "$generate_pdf" == "true" ]]; then
        save_as_pdf "$response"
    else
        echo "$response" | jq '.'

        # Print the analysis date
        print_submission_and_modification_dates "$response"
    fi
}

# Function to get a URL for uploading large files
get_upload_url() {
    response=$(curl --silent --request GET --url https://www.virustotal.com/api/v3/files/upload_url --header "x-apikey: $api_key")
    upload_url=$(echo "$response" | jq -r '.data')
    [[ $upload_url == null ]] && show_error "Error in getting upload URL: $response"
    echo "Upload URL obtained: $upload_url"
}

# Function to upload a file larger than 32MB using the obtained upload URL
upload_large_file() {
    response=$(curl --silent --request POST --url "$upload_url" --header "x-apikey: $api_key" --form file=@"$file")
    analysis_id=$(echo "$response" | jq -r '.data.id')
    [[ $analysis_id == null ]] && show_error "Error in large file upload: $response"
    echo "Large file uploaded successfully."
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

# Validate API key
[[ -z "$api_key" ]] && show_error "API key is required. Use the -a flag to provide it."

# Validate required options
[[ -z "$url" && -z "$file" ]] && show_error "Either a URL (-u) or a file (-f) must be provided."
[[ -n "$url" && -n "$file" ]] && show_error "Use only one of -u or -f at a time."
[[ -n "$file" && "$rescan" == "true" ]] && show_error "A rescan flag cannot be used when scanning a file - only usable with a URL scan."

# Main workflow
if [[ -n "$file" ]]; then
    [[ ! -f "$file" ]] && show_error "File not found: $file"
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
    if [[ "$rescan" == "true" ]]; then
        request_url_rescan_confirmation
    else
        id=$(submit_url)
        check_analysis_status "$id"
        get_url_report "$id"
    fi
fi
