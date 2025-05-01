#!/bin/bash

# Source credentials file
CREDENTIALS_FILE="$HOME/.aws/credentials"
PROFILES_DIR="$HOME/.aws/profiles"

# Create profiles directory if it doesn't exist
mkdir -p "$PROFILES_DIR"

# Function to extract profile content
extract_profile() {
    local profile_name=$1
    local start_line=$2
    local end_line=$3
    
    # Extract the profile content
    sed -n "${start_line},${end_line}p" "$CREDENTIALS_FILE" > "$PROFILES_DIR/${profile_name}.credentials"
}

# Get all profile names and their line numbers
profile_lines=$(grep -n "\[.*\]" "$CREDENTIALS_FILE")

# Process each profile
while IFS= read -r line; do
    profile_name=$(echo "$line" | sed 's/^[0-9]*:\[\(.*\)\]/\1/')
    start_line=$(echo "$line" | cut -d: -f1)
    
    # Find the next profile's start line or end of file
    next_profile_line=$(echo "$profile_lines" | grep -A1 "^$start_line:" | tail -n1 | cut -d: -f1)
    if [ -z "$next_profile_line" ]; then
        # If no next profile, use end of file
        end_line=$(wc -l < "$CREDENTIALS_FILE")
    else
        # Otherwise, use the line before the next profile
        end_line=$((next_profile_line - 1))
    fi
    
    echo "Creating profile: $profile_name"
    extract_profile "$profile_name" "$start_line" "$end_line"
done <<< "$profile_lines"

echo "All profiles have been broken out into individual files in $PROFILES_DIR" 
