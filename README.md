# URL Security Analysis Tool

## Overview
The **URL Security Analysis Tool** is a cybersecurity project designed to assess the safety of a given URL by performing multiple security checks. The tool leverages various APIs and security databases to detect potential threats, phishing attempts, and malware risks. The analysis results are stored in MongoDB for future reference and displayed on an interactive web dashboard.

## Features
- **SSL Certificate Validation**: Checks whether the given URL has a valid SSL certificate.
- **Domain Age Verification**: Determines the age of a domain to identify recently registered domains that may be suspicious.
- **WHOIS Information Lookup**: Fetches registration details of a domain.
- **Phishing Database Check**: Compares the URL against the OpenPhish database to detect phishing attempts.
- **VirusTotal URL Scan**: Uses the VirusTotal API to identify if the URL has been reported for malicious activity.
- **MongoDB Integration**: Stores analysis results for future reference and tracking.
- **Interactive Dashboard**: Displays results in an easy-to-read format.

## Technologies Used
- **Python**: Backend development and API integrations.
- **Flask**: Web framework to serve the dashboard.
- **MongoDB**: Database to store analysis reports.
- **Requests**: HTTP requests to access external APIs.
- **Whois**: Fetch domain registration information.
- **SSL**: Verify certificate validity.
- **HTML, CSS & JavaScript**: Frontend design for the web interface.

## Installation and Setup
1. **Clone the Repository**:
   ```sh
   git clone https://github.com/yourusername/url-security-analysis.git
   cd url-security-analysis
   ```

2. **Install Dependencies**:
   ```sh
   pip install -r requirements.txt
   ```

3. **Configure API Keys**:
   - Set up your API keys in `config.py`:
   ```python
   SERP_API_KEY = "your_serp_api_key"
   VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
   ```

4. **Run the Flask Server**:
   ```sh
   python app.py
   ```
   The web application will be available at `http://127.0.0.1:5000/`

## API Integrations
### 1. VirusTotal API
- The tool sends the given URL to VirusTotal for scanning.
- It retrieves multiple security reports including:
  - Number of security vendors flagging the URL.
  - Risk level (safe, suspicious, or malicious).
  - Additional metadata like last analysis date.

### 2. WHOIS Lookup
- Fetches information about the domain registrar, creation date, and expiration date.
- Helps in identifying recently created or suspicious domains.

### 3. OpenPhish Database
- The tool cross-checks URLs against the OpenPhish database to detect phishing attempts.

## Future Enhancements
- **AI-Powered URL Risk Prediction**: Implement an ML model to classify URLs based on their characteristics.
- **Browser Extension**: Develop a Chrome extension to analyze URLs in real-time.
- **Automated Reports**: Generate PDF reports of URL analyses.

## Contribution
- Fork the repository.
- Create a new branch.
- Submit a pull request with a detailed description of the changes.

## License
This project is licensed under the MIT License.

---
**Author**: Suryansh Ujjwal  
**Project Type**: Cybersecurity Research & Development




