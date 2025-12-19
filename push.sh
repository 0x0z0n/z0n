#!/bin/bash

# Check if a commit message was provided
if [ -z "$1" ]
then
  echo "Error: No commit message provided."
  echo "Usage: ./push.sh 'Your commit message'"
  exit 1
fi

# 1. Add all changes
git add .

# 2. Commit with the provided message
git commit -m "$1"

# 3. Push to the main branch
# Note: This will prompt for your password/PAT once unless cached
git push origin main
