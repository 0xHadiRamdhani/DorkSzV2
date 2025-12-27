# DorkSz v4.0 - SQL Injection Vulnerability Scanner

DorkSz is an advanced tool for finding websites vulnerable to SQL injection using Google dorking techniques. This tool has been completely rewritten for better compatibility, security, and user experience.

## Features

- **Google Dorking**: Search for potentially vulnerable websites using custom dorks
- **SQL Injection Detection**: Test websites for SQL injection vulnerabilities
- **Cross-Platform**: Works on macOS, Linux, and Windows
- **Multiple Payloads**: Comprehensive SQL error pattern detection
- **Detailed Reporting**: Summary statistics and vulnerability reports
- **Custom Output**: Save results to customizable output files
- **Command-Line Interface**: Modern CLI with arguments and options
- **Error Handling**: Robust error handling and logging
- **Performance**: Optimized scanning with timeout controls

## Installation

### Prerequisites
- Python 3.6 or higher
- pip package manager

### Install Dependencies
```bash
# Clone or download the repository
git clone https://github.com/0xHadiRamdhani/DorkSzV2
cd DorkSzV2

# Install required dependencies
pip install -r requirements.txt
```

### Required Dependencies
- `google>=3.0.0` - For Google search functionality
- `requests>=2.25.0` - For HTTP requests and vulnerability testing

## Usage

### Basic Usage
```bash
# Interactive mode (prompts for dork)
python3 DorkSz.py

# With specific dork
python3 DorkSz.py -d "inurl:admin.php?id="

# With custom output file
python3 DorkSz.py -d "inurl:product.php?id=" -o results.txt

# Limit search results
python3 DorkSz.py -d "inurl:category.php?id=" --max-results 50
```

### Advanced Usage
```bash
# Verbose mode for debugging
python3 DorkSz.py -d "inurl:news.php?id=" -v

# Comprehensive scan with custom output
python3 DorkSz.py -d "inurl:page.php?id=" -o vulnerable_sites.txt --max-results 200 -v
```

### Command Line Options
```bash
usage: DorkSz.py [-h] [-d DORK] [-o OUTPUT] [--max-results MAX_RESULTS] [-v]

DorkSz - SQL Injection Vulnerability Scanner

optional arguments:
  -h, --help            show this help message and exit
  -d DORK, --dork DORK  Google dork to search for vulnerable sites
  -o OUTPUT, --output OUTPUT
                        Output file for vulnerable URLs (default: vuln.txt)
  --max-results MAX_RESULTS
                        Maximum number of results to search (default: 100)
  -v, --verbose         Enable verbose output
```

## Example Dorks

Here are some example Google dorks you can use:

```
inurl:admin.php?id=
inurl:product.php?id=
inurl:category.php?id=
inurl:news.php?id=
inurl:page.php?id=
inurl:article.php?id=
inurl:show.php?id=
inurl:item.php?id=
inurl:content.php?id=
inurl:detail.php?id=
```

## How It Works

1. **Search Phase**: Uses Google dorking to find websites with potential SQL injection points
2. **Testing Phase**: Tests each found URL by appending SQL injection payloads
3. **Detection Phase**: Analyzes responses for SQL error patterns
4. **Reporting Phase**: Generates reports of vulnerable websites

## SQL Injection Detection

The tool detects various SQL error patterns including:
- MySQL errors (`mysql_fetch_array`, `mysql_error`, etc.)
- PostgreSQL errors (`PostgreSQL query failed`, etc.)
- SQLite errors (`SQLite3::`, `sqlite_error`, etc.)
- Oracle errors (`ORA-`, `Oracle error`, etc.)
- Microsoft SQL Server errors (`SQL Server`, etc.)
- Generic syntax errors (`syntax error`, `Unclosed quotation mark`, etc.)

## Output

### Console Output
- Real-time scanning progress
- Color-coded results (vulnerable/not vulnerable)
- Summary statistics
- Error messages and warnings

### File Output
- Saves vulnerable URLs to specified output file
- One URL per line
- UTF-8 encoded for international compatibility

## Error Handling

The tool includes comprehensive error handling for:
- Network timeouts and connection errors
- Invalid user input
- Missing dependencies
- File system errors
- Google search limitations

## Security Considerations

- **Responsible Use**: Only use this tool on websites you own or have permission to test
- **Rate Limiting**: The tool includes delays to avoid overwhelming target servers
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Ethical Hacking**: Use findings to improve security, not for malicious purposes

## Troubleshooting

### Common Issues

1. **Import Error**: Make sure all dependencies are installed
   ```bash
   pip install -r requirements.txt
   ```

2. **No Results Found**: Try different dorks or increase `--max-results`

3. **Network Errors**: Check your internet connection and try again

4. **Permission Errors**: Ensure write permissions for output file

### Debug Mode
Use `-v` flag for verbose output to see detailed error messages:
```bash
python3 DorkSz.py -d "inurl:test.php?id=" -v
```

## Version History

- **v4.0**: Complete rewrite with modern Python practices
- **v3.4**: Previous version (legacy)

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve the tool.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for misuse or damage caused by this tool.

## License

This project is licensed under the MIT License.

---

**Note**: This tool has been used by security researchers and the Blackhat team, specifically the Syborg Syndicate team, for legitimate security testing purposes.
