#!/bin/bash

# Function to display the help message
show_help() {
    echo "Usage: ./scanner.sh [-a api_key] [-u url] [-p] [-r] [-h]"
    echo "  -a: (Required) Set the API key for VirusTotal."
    echo "  -u: (Required) Set the URL to be scanned."
    echo "  -p: Generate a PDF report of the scan results."
    echo "  -r: Rescan the URL."
    echo "  -h: Display this help message."
}

# Function to submit URL for analysis
submit_url() {
    response=$(curl --silent --request POST --url https://www.virustotal.com/api/v3/urls --form url="$url" --header "x-apikey: $api_key")
    analysis_id=$(echo "$response" | jq -r '.data.id')
    if [[ $analysis_id == null ]]; then
        echo "Error in URL submission: $response"
        exit 1
    else
        echo "URL submitted successfully"
        echo "Analysis ID: $analysis_id"
    fi
    check_for_date_time "submit_url" "$response"
}

# Function to check analysis status
check_analysis_status() {
    local status="queued"
    local counter=0

    while [[ "$status" == "queued" && "$counter" -lt 10 ]]; do
        ((counter++))
        analysis_response=$(curl --silent --request GET --url "https://www.virustotal.com/api/v3/analyses/$analysis_id" --header "x-apikey: $api_key")
        status=$(echo "$analysis_response" | jq -r '.data.attributes.status')

        if [[ "$status" == "queued" ]]; then
            sleep 2
        fi
    done

    if [[ "$status" == "queued" ]]; then
        echo "Reached 10 API requests"
        echo "The analysis is taking longer than expected."
        exit 1
    else
        if [[ "$generate_pdf" == "false" ]]; then
            echo "Full analysis response:"
            echo "$analysis_response" | jq '.'
        fi
        response="$analysis_response"
        check_for_date_time "check_analysis_status" "$response"
    fi
}

# Function to request a URL rescan
request_url_rescan() {
    response=$(curl --silent --request POST --url https://www.virustotal.com/api/v3/urls/"$analysis_id"/analyse --header "x-apikey: $api_key")
    check_for_date_time "request_url_rescan" "$response"

    local status="queued"
    local counter=0

    while [[ "$status" == "queued" && "$counter" -lt 10 ]]; do
        ((counter++))
        analysis_response=$(curl --silent --request GET --url "https://www.virustotal.com/api/v3/analyses/$analysis_id" --header "x-apikey: $api_key")
        status=$(echo "$analysis_response" | jq -r '.data.attributes.status')

        if [[ "$status" == "queued" ]]; then
            sleep 2
        fi
    done

    if [[ "$status" == "queued" ]]; then
        echo "Reached 10 API requests"
        echo "The analysis is taking longer than expected."
        exit 1
    else
        if [[ "$generate_pdf" == "false" ]]; then
            echo "Full analysis response:"
            echo "$analysis_response" | jq '.'
        fi
        response="$analysis_response"
        check_for_date_time "request_url_rescan" "$response"
    fi
}

# Function to get URL/file analysis
get_url_file_analysis() {
    read -p "Do you want to proceed with the URL rescan? (y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
        request_url_rescan
        if [[ "$generate_pdf" == "true" ]]; then
            save_as_pdf
        fi
    else
        echo "Analysis canceled by the user."
        exit 0
    fi
}

# Function to save the response as a PDF
save_as_pdf() {
    timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
    domain=$(echo "$url" | awk -F/ '{print $3}' | sed 's/^www\.//')
    json_file=~/Desktop/"$domain"_"$timestamp"_report.json
    html_file=~/Desktop/"$domain"_"$timestamp"_report.html
    pdf_file=~/Desktop/"$domain"_"$timestamp"_report.pdf

    echo "$response" | jq '.' > "$json_file"

    echo "<html><body><pre>$(cat "$json_file")</pre></body></html>" > "$html_file"

    wkhtmltopdf "$html_file" "$pdf_file" > /dev/null 2>&1

    rm "$json_file" "$html_file"

    echo "PDF report generated at $pdf_file"
}

# Function to check for date/time values and print them in human-readable form
check_for_date_time() {
    local command="$1"
    local response="$2"
    local dates
    dates=$(echo "$response" | jq -r '.. | .date? // empty')

    if [[ -n "$dates" ]]; then
        echo "Command: $command"
        for date in $dates; do
            readable_date=$(date -r "$date" +"%Y-%m-%d %H:%M:%S")
            echo "Date: $readable_date"
        done
    fi
}

# Initialize variables
api_key=""
url=""
generate_pdf="false"
rescan="false"

# Parse command-line options
while getopts "a:u:prh" opt; do
    case $opt in
        a) api_key="$OPTARG" ;;
        u) url="$OPTARG" ;;
        p) generate_pdf="true" ;;
        r) rescan="true" ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

# Validate required options
if [[ -z "$api_key" || -z "$url" ]]; then
    show_help
    exit 1
fi

# Main workflow
if [[ "$rescan" == "true" ]]; then
    submit_url
    get_url_file_analysis
else
    submit_url
    check_analysis_status
    save_as_pdf
fi
