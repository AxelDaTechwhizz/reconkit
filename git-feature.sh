#!/bin/bash

FEATURE_NAME="$1"
COMMIT_MSG="$2"
VERSION="$3"

if [ -z "$FEATURE_NAME" ] || [ -z "$COMMIT_MSG" ]; then
  echo "Usage: ./git-feature.sh <feature-name> \"<commit-message>\" [version]"
  exit 1
fi

FEATURE_BRANCH="feature/$FEATURE_NAME"

# Ensure we're on main and up to date
git checkout main || exit 1
git pull origin main || exit 1

# Create or switch to feature branch
if git show-ref --verify --quiet refs/heads/"$FEATURE_BRANCH"; then
  echo "🔄 Switching to existing branch: $FEATURE_BRANCH"
  git checkout "$FEATURE_BRANCH"
else
  echo "🌱 Creating new branch: $FEATURE_BRANCH"
  git checkout -b "$FEATURE_BRANCH"
fi

# Stage, commit, and push
git add .
git commit -m "$COMMIT_MSG"
git push -u origin "$FEATURE_BRANCH"

# Open PR using GitHub CLI
if command -v gh >/dev/null 2>&1; then
  gh pr create --base main --head "$FEATURE_BRANCH" --title "$COMMIT_MSG" --body "$COMMIT_MSG"
else
  echo "⚠️ GitHub CLI not installed or not authenticated. PR not created."
fi

# Optional tagging and deployment
if [ -n "$VERSION" ]; then
  echo "🏷️ Tagging version v$VERSION"
  git tag "v$VERSION"
  git push origin "v$VERSION"
  echo "🚀 Deployment/tagging done for v$VERSION"
else
  echo "ℹ️ No version specified, skipping tagging and deployment."
fi
