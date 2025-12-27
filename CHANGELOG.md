# DorkSz Changelog

## Version 4.0 - Major Rewrite (2024-12-27)

### New Features
- **Complete Code Refactoring**: Rewritten from scratch with modern Python practices
- **Advanced CLI Interface**: Comprehensive command-line arguments and options
- **Multiple Output Formats**: Support for TXT, CSV, and JSON output formats
- **Custom Payload Support**: 28+ built-in SQL injection payloads with custom payload option
- **Rate Limiting**: Configurable delays between requests to be respectful to servers
- **Timeout Control**: Configurable request timeouts
- **Quiet Mode**: Minimal output for automated scripts
- **Verbose Mode**: Detailed debugging information
- **Update Checker**: Built-in update checking functionality
- **Payload List**: Display common SQL injection payloads
- **Cross-Platform Support**: Enhanced compatibility for macOS, Linux, and Windows

### Technical Improvements
- **Modular Architecture**: Separated into functions and modules
- **Proper Error Handling**: Comprehensive exception handling and logging
- **Input Validation**: Robust validation for all user inputs
- **Dependency Management**: requirements.txt for easy dependency installation
- **Configuration System**: Centralized configuration in config.py
- **Type Hints**: Added type hints for better code clarity
- **Documentation**: Comprehensive docstrings and comments

### New Files
- `requirements.txt` - Dependency management
- `config.py` - Configuration settings
- `setup.py` - Setup and installation script
- `install.sh` - Unix/Linux installation script
- `install.bat` - Windows installation script
- `compile.py` - Binary compilation script
- `example_dorks.txt` - Example Google dorks
- `CHANGELOG.md` - Version history
- `LICENSE` - MIT license
- `.gitignore` - Git ignore rules

### Security & Ethics
- **Responsible Use Warnings**: Clear disclaimers about ethical usage
- **Rate Limiting**: Built-in delays to prevent server overload
- **Legal Compliance**: Clear legal disclaimers and guidelines
- **Educational Purpose**: Emphasized educational and authorized testing only

### Bug Fixes
- **Cross-Platform Compatibility**: Fixed system() calls for macOS/Linux
- **Error Handling**: Replaced generic exception handling with specific handlers
- **Dependency Installation**: Removed dangerous automatic pip installs
- **Memory Management**: Better resource cleanup
- **Unicode Handling**: Proper UTF-8 encoding support

### Performance Improvements
- **Optimized Search**: Better Google search integration
- **Efficient Testing**: Improved SQL injection detection patterns
- **Memory Usage**: Reduced memory footprint
- **Faster Execution**: Optimized code execution paths

### Documentation
- **Comprehensive README**: Detailed usage instructions and examples
- **Installation Guides**: Step-by-step installation for all platforms
- **Usage Examples**: Multiple real-world usage scenarios
- **Troubleshooting**: Common issues and solutions
- **Ethical Guidelines**: Responsible use instructions

### User Experience
- **Interactive Mode**: User-friendly prompts
- **Progress Indicators**: Clear progress feedback during scans
- **Color-Coded Output**: Enhanced terminal output with colors
- **Help System**: Comprehensive help and usage information
- **Error Messages**: Clear and actionable error messages

## Previous Versions (Legacy)

### Version 3.4 and earlier
- Basic functionality with simple script structure
- Limited error handling
- Platform-specific issues
- No proper dependency management
- Minimal documentation

---

**Note**: Version 4.0 represents a complete rewrite and modernization of the DorkSz tool. All previous versions are considered legacy and should be upgraded to version 4.0 for better security, compatibility, and functionality.