#!/bin/bash

# AWS credential switcher script
# This script helps manage AWS credentials for multiple accounts

# Configuration
AWS_CREDENTIALS_DIR="$HOME/.aws/credentials"
AWS_CONFIG_DIR="$HOME/.aws/config"
BACKUP_DIR="$HOME/.aws/backups"
PROFILES_DIR="$HOME/.aws/profiles"

# Create necessary directories if they don't exist
mkdir -p "$BACKUP_DIR" "$PROFILES_DIR"

# Function to display usage information
show_usage() {
    echo "AWS Credential Switcher"
    echo "Usage: $0 [command] [profile]"
    echo ""
    echo "Commands:"
    echo "  list        - List all available profiles"
    echo "  save        - Save current credentials as a profile"
    echo "  switch      - Switch to a different profile"
    echo "  backup      - Create a backup of current credentials"
    echo "  restore     - Restore from a backup"
    echo ""
    echo "Examples:"
    echo "  $0 list"
    echo "  $0 save production"
    echo "  $0 switch staging"
    echo "  $0 backup"
    echo "  $0 restore 2024-04-22"
}

# Function to list available profiles
list_profiles() {
    echo "Available profiles:"
    ls -1 "$PROFILES_DIR" | sed 's/\.credentials$//' | sed 's/\.config$//' | sort | uniq
}

# Function to save current credentials as a profile
save_profile() {
    if [ -z "$1" ]; then
        echo "Error: Profile name is required"
        show_usage
        exit 1
    fi

    # Create timestamp for backup
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    
    # Backup current credentials
    cp "$AWS_CREDENTIALS_DIR" "$BACKUP_DIR/credentials_$TIMESTAMP"
    cp "$AWS_CONFIG_DIR" "$BACKUP_DIR/config_$TIMESTAMP"
    
    # Save as profile
    cp "$AWS_CREDENTIALS_DIR" "$PROFILES_DIR/$1.credentials"
    cp "$AWS_CONFIG_DIR" "$PROFILES_DIR/$1.config"
    
    echo "Profile '$1' saved successfully"
}

# Function to switch to a different profile
switch_profile() {
    if [ -z "$1" ]; then
        echo "Error: Profile name is required"
        show_usage
        exit 1
    fi

    if [ ! -f "$PROFILES_DIR/$1.credentials" ] || [ ! -f "$PROFILES_DIR/$1.config" ]; then
        echo "Error: Profile '$1' does not exist"
        exit 1
    fi

    # Create backup before switching
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    cp "$AWS_CREDENTIALS_DIR" "$BACKUP_DIR/credentials_$TIMESTAMP"
    cp "$AWS_CONFIG_DIR" "$BACKUP_DIR/config_$TIMESTAMP"
    
    # Switch to new profile
    cp "$PROFILES_DIR/$1.credentials" "$AWS_CREDENTIALS_DIR"
    cp "$PROFILES_DIR/$1.config" "$AWS_CONFIG_DIR"
    
    echo "Switched to profile '$1' successfully"
}

# Function to create a backup
create_backup() {
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    cp "$AWS_CREDENTIALS_DIR" "$BACKUP_DIR/credentials_$TIMESTAMP"
    cp "$AWS_CONFIG_DIR" "$BACKUP_DIR/config_$TIMESTAMP"
    echo "Backup created with timestamp: $TIMESTAMP"
}

# Function to restore from a backup
restore_backup() {
    if [ -z "$1" ]; then
        echo "Error: Backup timestamp is required"
        show_usage
        exit 1
    fi

    if [ ! -f "$BACKUP_DIR/credentials_$1" ] || [ ! -f "$BACKUP_DIR/config_$1" ]; then
        echo "Error: Backup with timestamp '$1' does not exist"
        exit 1
    fi

    cp "$BACKUP_DIR/credentials_$1" "$AWS_CREDENTIALS_DIR"
    cp "$BACKUP_DIR/config_$1" "$AWS_CONFIG_DIR"
    echo "Restored from backup: $1"
}

# Main script logic
case "$1" in
    list)
        list_profiles
        ;;
    save)
        save_profile "$2"
        ;;
    switch)
        switch_profile "$2"
        ;;
    backup)
        create_backup
        ;;
    restore)
        restore_backup "$2"
        ;;
    *)
        show_usage
        exit 1
        ;;
esac 
