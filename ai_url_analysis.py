import requests
import whois
import json
from urllib.parse import urlparse

# Set your API Keys here
SERP_API_KEY = "e08797ee6e7729658fa9713c67095463af68aea4227b0d388f5f2947ba8aaaae"
VIRUSTOTAL_API_KEY = "9c7fcc9fb15679dc6525c6c820887f4d8396171c11cdf3a8b181dbea05b08616"

def check_serpapi_blacklist(url):
    """Check if the URL appears in scam/malware/phishing results using SerpAPI."""
    query = f"site:{urlparse(url).netloc} scam OR malware OR phishing OR blacklist OR fraud"
    params = {"engine": "google", "q": query, "api_key": SERP_API_KEY}
    response = requests.get("https://serpapi.com/search", params=params)
    data = response.json()
    if "organic_results" in data and len(data["organic_results"]) > 0:
        return 1  # Flagged as suspicious
    return 0  # No issues found

def check_virustotal(url):
    """Check if the URL is flagged as malicious in VirusTotal."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{urlparse(url).netloc}", headers=headers)
    if response.status_code == 200:
        data = response.json()
        if "data" in data and "attributes" in data["data"]:
            malicious_count = data["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
            return malicious_count
    return 0

def get_domain_age(url):
    """Get the domain age from WHOIS data."""
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)
        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date
        if creation_date:
            return 1 if (2025 - creation_date.year) < 2 else 0  # Risk if domain is new
    except:
        return 1  # Risk if WHOIS fails
    return 0

def check_https(url):
    """Check if HTTPS is used."""
    return 0 if url.startswith("https://") else 1

def calculate_risk_score(url):
    """Calculate a risk score for the given URL."""
    score = 0
    score += check_serpapi_blacklist(url) * 20
    score += check_virustotal(url) * 15
    score += get_domain_age(url) * 10
    score += check_https(url) * 10
    return min(100, score)

def analyze_url(url):
    """Perform a full AI-powered URL risk analysis."""
    risk_score = calculate_risk_score(url)
    print("\n🔍 URL Analysis Report:")
    print(f"🌐 URL: {url}")
    print(f"⚠️ Risk Score: {risk_score}/100")
    print("✅ Safe" if risk_score < 40 else "⚠️ Potential Risk!" if risk_score < 70 else "❌ Dangerous!")

# Run the AI Analysis
if __name__ == "__main__":
    user_url = input("Enter the URL to analyze: ")
    analyze_url(user_url)
