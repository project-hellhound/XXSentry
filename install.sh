#!/bin/bash
# install.sh — Setup for xssentry v4.0 [HELLHOUND-class]

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}[*] Starting xssentry installation...${NC}"

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 is required but not installed. Aborting.${NC}"
    exit 1
fi

# Create virtual environment
echo -e "${BLUE}[*] Creating virtual environment (.venv)...${NC}"
python3 -m venv .venv
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Failed to create virtual environment. Ensure 'python3-venv' is installed.${NC}"
    exit 1
fi

# Define pip and python from venv
VENV_PIP="./.venv/bin/pip"
VENV_PYTHON="./.venv/bin/python3"

echo -e "${BLUE}[*] Installing dependencies in venv...${NC}"
$VENV_PIP install --upgrade pip
$VENV_PIP install playwright aiohttp beautifulsoup4 lxml

# Install playwright browsers in venv
echo -e "${BLUE}[*] Installing Playwright browsers...${NC}"
$VENV_PYTHON -m playwright install chromium

# Setup CLI command via wrapper
echo -e "${BLUE}[*] Creating xssentry wrapper...${NC}"
cat <<EOF > xssentry
#!/bin/bash
REAL_PATH=\$(dirname "\$(readlink -f "\$0")")
"\$REAL_PATH/.venv/bin/python3" "\$REAL_PATH/xssentry.py" "\$@"
EOF
chmod +x xssentry

# Install the package in editable mode within venv
echo -e "${BLUE}[*] Finalizing setup...${NC}"
$VENV_PIP install -e .

# Create global symbolic link
echo -e "${BLUE}[*] Creating global symbolic link in /usr/local/bin/xssentry...${NC}"
REAL_WRAPPER_PATH=$(readlink -f "xssentry")
if [ -w "/usr/local/bin" ]; then
    ln -sf "$REAL_WRAPPER_PATH" /usr/local/bin/xssentry
    GLOBAL_OK=1
else
    echo -e "${YELLOW}[!] Permission denied for /usr/local/bin. Attempting with sudo...${NC}"
    sudo ln -sf "$REAL_WRAPPER_PATH" /usr/local/bin/xssentry
    if [ $? -eq 0 ]; then GLOBAL_OK=1; fi
fi

if [ $? -eq 0 ] && [ "$GLOBAL_OK" == "1" ]; then
    echo -e "${GREEN}[+] xssentry installed successfully!${NC}"
    echo -e "${YELLOW}[!] You can now run 'xssentry' from anywhere in your terminal.${NC}"
else
    echo -e "${GREEN}[+] xssentry installed locally.${NC}"
    echo -e "${YELLOW}[!] Global link failed. You can still run it as './xssentry' or add this directory to your PATH.${NC}"
fi
