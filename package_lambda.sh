#!/bin/bash
# Script to package Lambda function code into a deployment zip file

set -e

echo "Packaging Lambda function..."

# Create a temporary directory for packaging
TEMP_DIR=$(mktemp -d)
echo "Using temporary directory: $TEMP_DIR"

# Copy Lambda function to temp directory
cp lambda_function.py "$TEMP_DIR/index.py"

# Create zip file
cd "$TEMP_DIR"
zip -q lambda_function.zip index.py

# Move zip back to workspace
mv lambda_function.zip "$OLDPWD/"

# Cleanup
cd "$OLDPWD"
rm -rf "$TEMP_DIR"

echo "Lambda function packaged successfully: lambda_function.zip"
echo "File size: $(ls -lh lambda_function.zip | awk '{print $5}')"
