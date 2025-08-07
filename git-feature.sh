#!/bin/bash

FEATURE_NAME=$1
COMMIT_MSG=$2
NEW_VERSION=$3  # e.g., 2.1.0

if [ -z "$FEATURE_NAME" ] || [ -z "$COMMIT_MSG" ]; then
  echo "Usage: ./git-feature.sh <feature-name> <commit-message> [new-version]"
  echo "Example: ./git-feature.sh traffic-interception 'Add traffic interception' 2.1.0"
  exit 1
fi

# Step 1: Update main branch
git checkout main && git pull origin main

# Step 2: Create and switch to feature branch
git checkout -b feature/$FEATURE_NAME

# Step 3: Add and commit changes
git add .
git commit -m "$COMMIT_MSG"

# Step 4: Push branch to origin
git push -u origin feature/$FEATURE_NAME

# Step 5: Open a PR using GitHub CLI
echo "Opening PR..."
gh pr create --fill --title "Feature: $FEATURE_NAME" --body "$COMMIT_MSG"

# Step 6: If new version specified, tag and push tag (run only after PR is merged)
if [ ! -z "$NEW_VERSION" ]; then
  echo "Tagging new version: v$NEW_VERSION"

  # Make sure you are on main and up to date before tagging
  git checkout main
  git pull origin main

  # Create annotated tag
  git tag -a "v$NEW_VERSION" -m "Release version $NEW_VERSION - $FEATURE_NAME"

  # Push tag
  git push origin "v$NEW_VERSION"

  # Step 7: Deploy (add your deploy commands here)
  echo "Running deployment steps..."
  # Example: ./deploy.sh or ssh user@server 'deploy commands'
  # ./deploy.sh

  echo "Deployment finished."
else
  echo "No version specified, skipping tagging and deployment."
fi
