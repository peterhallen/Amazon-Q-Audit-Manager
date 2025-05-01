#!/bin/bash
# setup-hooks.sh - Install git hooks

# Create hooks directory if it doesn't exist
mkdir -p .git/hooks

# Copy pre-commit hook
cp hooks/pre-commit .git/hooks/pre-commit

# Make hooks executable
chmod +x .git/hooks/pre-commit

echo "Git hooks installed successfully!"
