#!/usr/bin/env python3
"""
DorkSz Binary Compiler
Compile DorkSz to standalone executable for easy distribution
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

def print_banner():
    """Print compiler banner"""
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
    print("\033[33mDorkSz Binary Compiler v1.0\033[0m")
    print("\033[33mAuthor: HadsXdevPy\033[0m")
    print()

def check_dependencies():
    """Check if required dependencies are available"""
    print("\033[34m[INFO] Checking dependencies...\033[0m")
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print("\033[32m[✓] PyInstaller found\033[0m")
        return True
    except ImportError:
        print("\033[31m[ERROR] PyInstaller not found!\033[0m")
        print("\033[33mInstalling PyInstaller...\033[0m")
        
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
            print("\033[32m[✓] PyInstaller installed successfully\033[0m")
            return True
        except subprocess.CalledProcessError as e:
            print(f"\033[31m[ERROR] Failed to install PyInstaller: {e}\033[0m")
            return False

def check_source_files():
    """Check if source files exist"""
    print("\033[34m[INFO] Checking source files...\033[0m")
    
    required_files = ['DorkSz.py', 'requirements.txt']
    missing_files = []
    
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print(f"\033[31m[ERROR] Missing files: {', '.join(missing_files)}\033[0m")
        return False
    
    print("\033[32m[✓] All source files found\033[0m")
    return True

def create_spec_file():
    """Create PyInstaller spec file"""
    print("\033[34m[INFO] Creating PyInstaller spec file...\033[0m")
    
    spec_content = """# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['DorkSz.py'],
    pathex=[],
    binaries=[],
    datas=[('requirements.txt', '.'), ('example_dorks.txt', '.'), ('config.py', '.'), ('README.md', '.'), ('LICENSE', '.')],
    hiddenimports=['googlesearch', 'requests'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='DorkSz',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
"""
    
    try:
        with open('DorkSz.spec', 'w') as f:
            f.write(spec_content)
        print("\033[32m[✓] Spec file created\033[0m")
        return True
    except Exception as e:
        print(f"\033[31m[ERROR] Failed to create spec file: {e}\033[0m")
        return False

def compile_binary():
    """Compile the binary using PyInstaller"""
    print("\033[34m[INFO] Compiling binary...\033[0m")
    
    # Clean previous builds
    if os.path.exists('build'):
        shutil.rmtree('build')
    if os.path.exists('dist'):
        shutil.rmtree('dist')
    if os.path.exists('__pycache__'):
        shutil.rmtree('__pycache__')
    
    try:
        # Use PyInstaller to compile
        cmd = [
            sys.executable, '-m', 'PyInstaller',
            '--onefile',
            '--name', 'DorkSz',
            '--distpath', './dist',
            '--workpath', './build',
            '--specpath', '.',
            '--clean',
            '--noconfirm',
            'DorkSz.py'
        ]
        
        print("\033[34m[INFO] Running PyInstaller...\033[0m")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("\033[32m[✓] Compilation successful!\033[0m")
            return True
        else:
            print(f"\033[31m[ERROR] Compilation failed:\033[0m")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"\033[31m[ERROR] Compilation error: {e}\033[0m")
        return False

def test_binary():
    """Test the compiled binary"""
    print("\033[34m[INFO] Testing compiled binary...\033[0m")
    
    binary_name = 'DorkSz.exe' if platform.system() == 'Windows' else 'DorkSz'
    binary_path = os.path.join('dist', binary_name)
    
    if not os.path.exists(binary_path):
        print(f"\033[31m[ERROR] Binary not found: {binary_path}\033[0m")
        return False
    
    try:
        # Test version command
        result = subprocess.run([binary_path, '--version'], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and 'DorkSz v4.0' in result.stdout:
            print("\033[32m[✓] Binary test passed!\033[0m")
            return True
        else:
            print(f"\033[31m[ERROR] Binary test failed:\033[0m")
            print(f"Return code: {result.returncode}")
            print(f"Output: {result.stdout}")
            print(f"Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("\033[31m[ERROR] Binary test timed out\033[0m")
        return False
    except Exception as e:
        print(f"\033[31m[ERROR] Binary test error: {e}\033[0m")
        return False

def create_distribution_package():
    """Create distribution package with all necessary files"""
    print("\033[34m[INFO] Creating distribution package...\033[0m")
    
    dist_dir = 'DorkSz_Distribution'
    
    # Clean previous distribution
    if os.path.exists(dist_dir):
        shutil.rmtree(dist_dir)
    
    try:
        os.makedirs(dist_dir)
        
        # Copy binary
        binary_name = 'DorkSz.exe' if platform.system() == 'Windows' else 'DorkSz'
        binary_path = os.path.join('dist', binary_name)
        shutil.copy2(binary_path, dist_dir)
        
        # Copy documentation files
        doc_files = ['README.md', 'LICENSE', 'example_dorks.txt', 'requirements.txt']
        for file in doc_files:
            if os.path.exists(file):
                shutil.copy2(file, dist_dir)
        
        # Create installation script
        install_script = create_install_script()
        with open(os.path.join(dist_dir, 'INSTALL.txt'), 'w') as f:
            f.write(install_script)
        
        print(f"\033[32m[✓] Distribution package created: {dist_dir}\033[0m")
        return True
        
    except Exception as e:
        print(f"\033[31m[ERROR] Failed to create distribution package: {e}\033[0m")
        return False

def create_install_script():
    """Create installation instructions"""
    system = platform.system()
    
    if system == 'Windows':
        return """DorkSz Binary Installation Instructions (Windows)
================================================

1. Make sure you have the DorkSz.exe file
2. Place it in your desired directory
3. Open Command Prompt or PowerShell
4. Navigate to the directory containing DorkSz.exe
5. Run: DorkSz.exe --help

Usage Examples:
  DorkSz.exe -d "inurl:admin.php?id=" -o results.txt
  DorkSz.exe -d "inurl:product.php?id=" --max-results 50
  DorkSz.exe --list-payloads

For more information, see README.md
"""
    else:
        return """DorkSz Binary Installation Instructions (macOS/Linux)
===================================================

1. Make the binary executable:
   chmod +x DorkSz

2. Run the binary:
   ./DorkSz --help

3. Optionally, move to a directory in your PATH:
   sudo mv DorkSz /usr/local/bin/

Usage Examples:
  ./DorkSz -d "inurl:admin.php?id=" -o results.txt
  ./DorkSz -d "inurl:product.php?id=" --max-results 50
  ./DorkSz --list-payloads

For more information, see README.md
"""

def main():
    """Main compilation function"""
    print_banner()
    
    print("\033[34m[INFO] Starting DorkSz compilation...\033[0m")
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check source files
    if not check_source_files():
        sys.exit(1)
    
    # Compile binary
    if not compile_binary():
        sys.exit(1)
    
    # Test binary
    if not test_binary():
        sys.exit(1)
    
    # Create distribution package
    if not create_distribution_package():
        sys.exit(1)
    
    # Final message
    print("\n\033[32m[✓] Compilation completed successfully!\033[0m")
    print(f"\n\033[33mBinary location: dist/DorkSz{'.exe' if platform.system() == 'Windows' else ''}\033[0m")
    print(f"\033[33mDistribution package: DorkSz_Distribution/\033[0m")
    print("\n\033[33mThe binary is ready for distribution!\033[0m")
    print("\033[33mUsers can run it without installing Python dependencies.\033[0m")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[31m[INFO] Compilation interrupted by user\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\033[31m[ERROR] Compilation failed: {e}\033[0m")
        sys.exit(1)