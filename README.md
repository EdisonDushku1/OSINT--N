# OSINT--N
**All in ONE OSINT Tool** - A comprehensive Open Source Intelligence toolkit for information gathering and reconnaissance.

## Overview
OSINT--N is designed to streamline OSINT operations by providing a unified interface for multiple reconnaissance techniques and data collection methods. Perfect for security researchers, penetration testers, and investigators.

## Features
- Multi-source information gathering
- Domain and IP reconnaissance
- User/Account discovery
- Email verification
- Social media tracking
- Web scraping capabilities
- Data aggregation and reporting

## Installation

### Prerequisites
- Python 3.8 or higher
- Git
- pip (Python package manager)

### Quick Start
```bash
# Clone the repository
git clone https://github.com/EdisonDushku1/OSINT--N.git
cd OSINT--N

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Commands
```bash
# Display help menu
python main.py --help

# Search email information
python main.py --email user@example.com

# Run with specific module
python main.py --module [module_name]

# Search for domain information
python main.py --domain example.com
```

### Examples
```bash
# Email reconnaissance
python main.py --email test@gmail.com

# Domain reconnaissance
python main.py --domain target.com

# IP address lookup
python main.py --ip 192.168.1.1

# Username search across platforms
python main.py --username targetuser
```

## Supported OSINT Methods
- Domain WHOIS lookups
- DNS enumeration
- IP geolocation
- Reverse DNS lookup
- Email validation & tracking
- Social media OSINT
- Web archive searches
- Subdomain discovery
- Breach database searches

## Configuration
Edit the `config.json` file to customize:
- API keys for external services
- Search parameters
- Output formats
- Proxy settings
- Rate limiting options

## Requirements
See `requirements.txt` for all dependencies. Key libraries include:
- requests
- beautifulsoup4
- dnspython
- selenium (for browser automation)

## Output
Results are saved in multiple formats:
- JSON
- CSV
- HTML report
- Console output

## Legal & Ethical Notice
⚠️ **IMPORTANT**: This tool is for **authorized security testing and research only**. Users are responsible for:
- Obtaining proper authorization before any reconnaissance
- Complying with all applicable laws and regulations
- Respecting privacy and terms of service
- Understanding the legal implications of OSINT activities

**Unauthorized access to computer systems is illegal.**

## Troubleshooting

### Common Issues
- **Module not found**: Ensure all dependencies are installed with `pip install -r requirements.txt`
- **API errors**: Check your API keys in `config.json`
- **Permission denied**: Make sure the script has execute permissions: `chmod +x main.py`
- **Rate limiting**: Some services have request limits; consider adding delays between queries

## Contributing
Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/YourFeature`)
3. Commit changes (`git commit -m "Add YourFeature"`)
4. Push to branch (`git push origin feature/YourFeature`)
5. Open a Pull Request

## License
[Specify your license here, e.g., MIT, GPL-3.0, etc.]

## Support & Issues
Found a bug or have a suggestion? Please [open an issue](https://github.com/EdisonDushku1/OSINT--N/issues) on GitHub.

## Disclaimer
This tool is provided as-is for educational and authorized security purposes. The authors assume no liability for misuse or damages caused by this tool.

---

**Last Updated**: 2026-05-04
