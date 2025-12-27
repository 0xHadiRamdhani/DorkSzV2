#!/usr/bin/env python3
"""
Setup script for DorkSz - SQL Injection Vulnerability Scanner
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_banner():
    """Print setup banner"""
    banner = """
  ______                    __      _______         
 |   _  \   .-----. .----. |  |--. |   _   | .-----.
 |.  |   \  |  _  | |   _| |    <  |___|   | |__ --|
 |.  |    \ |_____| |__|   |__|__|  /  ___/  |_____|
 |:  1    /                        |:  1  \         
 |::.. . /                         |::.. . |        
 `------'                          `-------'        
    """
    print("\033[31m" + banner + "\033[0m")
    print("\033[33mDorkSz Setup Script v4.0\033[0m")
    print("\033[33mAuthor: HadsXdevPy\033[0m")
    print()

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 6):
        print("\033[31m[ERROR] Python 3.6 or higher is required!\033[0m")
        print(f"\033[33mCurrent version: {sys.version}\033[0m")
        return False
    print("\033[32m[✓] Python version check passed\033[0m")
    return True

def install_dependencies():
    """Install required dependencies"""
    print("\033[34m[INFO] Installing dependencies...\033[0m")
    
    try:
        # Upgrade pip first
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        
        # Install requirements
        if os.path.exists("requirements.txt"):
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            print("\033[32m[✓] Dependencies installed successfully\033[0m")
            return True
        else:
            print("\033[31m[ERROR] requirements.txt not found!\033[0m")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"\033[31m[ERROR] Failed to install dependencies: {e}\033[0m")
        return False
    except Exception as e:
        print(f"\033[31m[ERROR] Unexpected error: {e}\033[0m")
        return False

def check_dependencies():
    """Check if all dependencies are installed"""
    print("\033[34m[INFO] Checking dependencies...\033[0m")
    
    missing_deps = []
    
    try:
        import googlesearch
        print("\033[32m[✓] googlesearch module found\033[0m")
    except ImportError:
        missing_deps.append("googlesearch")
        print("\033[31m[✗] googlesearch module not found\033[0m")
    
    try:
        import requests
        print("\033[32m[✓] requests module found\033[0m")
    except ImportError:
        missing_deps.append("requests")
        print("\033[31m[✗] requests module not found\033[0m")
    
    if missing_deps:
        print(f"\033[31m[ERROR] Missing dependencies: {', '.join(missing_deps)}\033[0m")
        return False
    
    print("\033[32m[✓] All dependencies are available\033[0m")
    return True

def make_executable():
    """Make the main script executable on Unix-like systems"""
    if platform.system() != "Windows":
        try:
            os.chmod("DorkSz.py", 0o755)
            print("\033[32m[✓] Made DorkSz.py executable\033[0m")
            return True
        except Exception as e:
            print(f"\033[33m[WARNING] Could not make script executable: {e}\033[0m")
            return False
    return True

def create_test_file():
    """Create a test file with example dorks"""
    test_content = """# Example DorkSz Test Dorks
# Use these dorks to test the tool

# Basic SQL injection dorks
inurl:admin.php?id=
inurl:product.php?id=
inurl:category.php?id=
inurl:news.php?id=
inurl:page.php?id=

# Advanced dorks
inurl:article.php?id= intitle:"news"
inurl:show.php?id= site:.com
inurl:item.php?id= site:.org

# WordPress dorks
inurl:wp-content/plugins/ intext:"index of"
inurl:wp-admin/ intext:"login"

# Custom dorks (add your own)
# inurl:custom.php?id=
# inurl:your_target.php?id=
"""
    
    try:
        with open("test_dorks.txt", "w") as f:
            f.write(test_content)
        print("\033[32m[✓] Created test_dorks.txt with example dorks\033[0m")
        return True
    except Exception as e:
        print(f"\033[33m[WARNING] Could not create test file: {e}\033[0m")
        return False

def main():
    """Main setup function"""
    print_banner()
    
    print("\033[34m[INFO] Starting DorkSz setup...\033[0m")
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("\033[31m[ERROR] Setup failed during dependency installation\033[0m")
        sys.exit(1)
    
    # Verify dependencies
    if not check_dependencies():
        print("\033[31m[ERROR] Dependency verification failed\033[0m")
        sys.exit(1)
    
    # Make executable
    make_executable()
    
    # Create test file
    create_test_file()
    
    print("\n\033[32m[✓] Setup completed successfully!\033[0m")
    print("\n\033[33m=== Usage Examples ===\033[0m")
    print("\033[36m# Interactive mode:\033[0m")
    print("python3 DorkSz.py")
    print("\n\033[36m# With specific dork:\033[0m")
    print("python3 DorkSz.py -d \"inurl:admin.php?id=\"")
    print("\n\033[36m# With custom output:\033[0m")
    print("python3 DorkSz.py -d \"inurl:product.php?id=\" -o results.txt")
    print("\n\033[36m# For help:\033[0m")
    print("python3 DorkSz.py --help")
    print("\n\033[33mHappy scanning! Remember to use responsibly.\033[0m")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[31m[INFO] Setup interrupted by user\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\033[31m[ERROR] Setup failed: {e}\033[0m")
        sys.exit(1)