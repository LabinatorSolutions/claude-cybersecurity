#!/usr/bin/env bash
set -euo pipefail

SKILL_NAME="cybersecurity"
SKILL_DIR="$HOME/.claude/skills/$SKILL_NAME"
REPO_URL="https://github.com/AgriciDaniel/claude-cybersecurity"

echo "Installing $SKILL_NAME..."

# Create skill directory
mkdir -p "$SKILL_DIR/references/language-patterns"
mkdir -p "$SKILL_DIR/references/iac-patterns"

# Clone or update
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

git clone --depth 1 "$REPO_URL.git" "$TEMP_DIR" 2>/dev/null || {
    echo "Error: Could not clone repository. Check your internet connection."
    exit 1
}

# Copy skill files
cp "$TEMP_DIR/skills/$SKILL_NAME/SKILL.md" "$SKILL_DIR/"
cp "$TEMP_DIR/skills/$SKILL_NAME/references/"*.md "$SKILL_DIR/references/"
cp "$TEMP_DIR/skills/$SKILL_NAME/references/language-patterns/"*.md "$SKILL_DIR/references/language-patterns/"
cp "$TEMP_DIR/skills/$SKILL_NAME/references/iac-patterns/"*.md "$SKILL_DIR/references/iac-patterns/"

echo ""
echo "claude-cybersecurity installed successfully!"
echo ""
echo "Usage:"
echo "  /cybersecurity              # Full security audit"
echo "  /cybersecurity --scope quick # Quick scan"
echo "  /cybersecurity --scope diff  # PR review mode"
echo ""
