#!/bin/bash
# update.sh — Update xssentry and its venv

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}[*] Checking for updates...${NC}"

# Pull latest changes
git pull origin main

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Successfully pulled latest changes.${NC}"
    
    if [ -d ".venv" ]; then
        echo -e "${BLUE}[*] Updating dependencies in .venv...${NC}"
        ./.venv/bin/pip install --upgrade pip
        ./.venv/bin/pip install -e .
        echo -e "${GREEN}[+] Dependencies updated.${NC}"
    else
        echo -e "${RED}[!] Virtual environment not found. Please run ./install.sh${NC}"
    fi
    
    echo -e "${GREEN}[+] xssentry updated to latest version!${NC}"
else
    echo -e "${RED}[!] Update failed. Check your network or git configuration.${NC}"
    exit 1
fi
