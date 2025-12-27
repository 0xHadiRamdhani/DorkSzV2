#!/bin/bash
# DorkSz Installation Script for Unix-like systems (macOS/Linux)

set -e  # Exit on any error

# Colors for output
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
WHITE='\033[37m'
NC='\033[0m' # No Color

# Banner
echo -e "${RED}"
echo "  ______                    __      _______         "
echo " |   _  \   .-----. .----. |  |--. |   _   | .-----. "
echo " |.  |   \  |  _  | |   _| |    <  |___|   | |__ --| "
echo " |.  |    \ |_____| |__|   |__|__|  /  ___/  |_____| "
echo " |:  1    /                        |:  1  \         "
echo " |::.. . /                         |::.. . |        "
echo " \`------'                          \`-------'        "
echo -e "${NC}"
echo -e "${YELLOW}DorkSz Installation Script${NC}"
echo -e "${YELLOW}Author: HadsXdevPy${NC}"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python 3
echo -e "${BLUE}[INFO] Checking Python 3 installation...${NC}"
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}[✓] Python 3 found: $PYTHON_VERSION${NC}"
else
    echo -e "${RED}[ERROR] Python 3 is not installed!${NC}"
    echo -e "${YELLOW}Please install Python 3.6 or higher and try again.${NC}"
    exit 1
fi

# Check pip3
echo -e "${BLUE}[INFO] Checking pip3...${NC}"
if command_exists pip3; then
    echo -e "${GREEN}[✓] pip3 found${NC}"
else
    echo -e "${RED}[ERROR] pip3 is not installed!${NC}"
    echo -e "${YELLOW}Please install pip3 and try again.${NC}"
    exit 1
fi

# Create virtual environment
echo -e "${BLUE}[INFO] Creating virtual environment...${NC}"
if [ -d "venv" ]; then
    echo -e "${YELLOW}[WARNING] Virtual environment already exists, removing...${NC}"
    rm -rf venv
fi

python3 -m venv venv
echo -e "${GREEN}[✓] Virtual environment created${NC}"

# Activate virtual environment
echo -e "${BLUE}[INFO] Activating virtual environment...${NC}"
source venv/bin/activate

# Upgrade pip
echo -e "${BLUE}[INFO] Upgrading pip...${NC}"
pip install --upgrade pip

# Install dependencies
echo -e "${BLUE}[INFO] Installing dependencies...${NC}"
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    echo -e "${GREEN}[✓] Dependencies installed${NC}"
else
    echo -e "${RED}[ERROR] requirements.txt not found!${NC}"
    exit 1
fi

# Make scripts executable
echo -e "${BLUE}[INFO] Making scripts executable...${NC}"
chmod +x DorkSz.py
chmod +x setup.py

# Create activation script
echo -e "${BLUE}[INFO] Creating activation script...${NC}"
cat > activate_dorksz.sh << 'EOF'
#!/bin/bash
# DorkSz Activation Script

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Activate virtual environment
source "$SCRIPT_DIR/venv/bin/activate"

echo "DorkSz environment activated!"
echo "You can now run: python3 DorkSz.py --help"
echo ""

# Show current directory
echo "Current directory: $SCRIPT_DIR"
echo ""

# Show help
python3 DorkSz.py --help
EOF

chmod +x activate_dorksz.sh

# Test installation
echo -e "${BLUE}[INFO] Testing installation...${NC}"
if python3 -c "import googlesearch, requests; print('Import test passed')" 2>/dev/null; then
    echo -e "${GREEN}[✓] Installation test passed${NC}"
else
    echo -e "${RED}[ERROR] Installation test failed!${NC}"
    exit 1
fi

# Create desktop shortcut (optional)
echo -e "${BLUE}[INFO] Creating desktop shortcut...${NC}"
if [ -d "$HOME/Desktop" ] || [ -d "$HOME/Desktop" ]; then
    DESKTOP_DIR="$HOME/Desktop"
    if [ -d "$HOME/Desktop" ]; then
        DESKTOP_DIR="$HOME/Desktop"
    fi
    
    cat > "$DESKTOP_DIR/DorkSz.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=DorkSz
Comment=SQL Injection Vulnerability Scanner
Exec=gnome-terminal --working-directory=$(pwd) -e "bash -c 'source venv/bin/activate && python3 DorkSz.py; exec bash'"
Icon=utilities-terminal
Terminal=true
Categories=Development;Security;
EOF
    
    chmod +x "$DESKTOP_DIR/DorkSz.desktop" 2>/dev/null || true
    echo -e "${GREEN}[✓] Desktop shortcut created${NC}"
fi

# Final message
echo ""
echo -e "${GREEN}[✓] Installation completed successfully!${NC}"
echo ""
echo -e "${YELLOW}=== Usage Instructions ===${NC}"
echo -e "${WHITE}# To activate the environment:${NC}"
echo -e "${BLUE}source activate_dorksz.sh${NC}"
echo ""
echo -e "${WHITE}# Or manually activate:${NC}"
echo -e "${BLUE}source venv/bin/activate${NC}"
echo -e "${BLUE}python3 DorkSz.py --help${NC}"
echo ""
echo -e "${WHITE}# Example usage:${NC}"
echo -e "${BLUE}python3 DorkSz.py -d \"inurl:admin.php?id=\" -o results.txt${NC}"
echo ""
echo -e "${YELLOW}Happy scanning! Remember to use responsibly.${NC}"
echo -e "${YELLOW}Only test websites you own or have permission to test.${NC}"