import requests
import whois
import json
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

SERP_API_KEY = "e08797ee6e7729658fa9713c67095463af68aea4227b0d388f5f2947ba8aaaae"
VIRUSTOTAL_API_KEY = "9c7fcc9fb15679dc6525c6c820887f4d8396171c11cdf3a8b181dbea05b08616"

def check_serpapi_blacklist(url):
    """Check if the URL appears in scam-related Google search results."""
    domain = urlparse(url).netloc
    query = f"site:{domain} scam OR phishing OR malware OR fraud"
    
    params = {"engine": "google", "q": query, "api_key": SERP_API_KEY}
    response = requests.get("https://serpapi.com/search", params=params)
    
    if response.status_code != 200:
        return 0  # If API fails, assume safe
    
    data = response.json()
    if "organic_results" in data and len(data["organic_results"]) > 0:
        return 10  # High risk if scam-related pages exist
    
    return 0  # Safe if no scam reports found

def check_virustotal(url):
    """Check if the URL is flagged as malicious on VirusTotal."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
    
    if response.status_code != 200:
        return 0  # Assume safe if API request fails

    try:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        analysis_stats = attributes.get("last_analysis_stats", {})
        malicious_count = analysis_stats.get("malicious", 0)
        return min(malicious_count * 5, 50)  # Max 50 points for VirusTotal threats
    except Exception as e:
        print(f"Error processing VirusTotal response: {e}")
        return 0  # Assume safe in case of error

def get_domain_age(url):
    """Determine domain age based on WHOIS data."""
    domain = urlparse(url).netloc
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # Calculate age in years
        if creation_date:
            age = (2025 - creation_date.year) if hasattr(creation_date, "year") else 0
            return max(10 - age, 0) * 3  # Max 30 points for young domains

    except:
        return 10  # Assign medium risk if WHOIS fails

    return 0  # Safe if domain is old

def check_https(url):
    """Check if the URL uses HTTPS."""
    return 0 if url.startswith("https://") else 10  # 10 points if insecure (HTTP)

def scrape_website(url):
    """Extract metadata from the webpage (title & description)."""
    try:
        response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string if soup.title else "No Title"
        description = soup.find("meta", attrs={"name": "description"})
        description = description["content"] if description else "No Description"
        return {"title": title, "description": description}
    except:
        return {"title": "Error fetching website", "description": "N/A"}

def calculate_risk_score(url):
    """Generate a risk score (0-100) based on multiple security checks."""
    score = 0
    score += check_serpapi_blacklist(url)  # 10 points max
    score += check_virustotal(url)         # 50 points max
    score += get_domain_age(url)           # 30 points max
    score += check_https(url)              # 10 points max
    
    return min(score, 100)  # Ensure score doesn't exceed 100

def analyze_url(url):
    """Perform a complete security analysis of the given URL."""
    print("\n🔍 Analyzing:", url)

    # Get website metadata
    metadata = scrape_website(url)

    # Calculate risk score
    risk_score = calculate_risk_score(url)
    
    # Display report
    report = {
        "Website Title": metadata["title"],
        "Website Description": metadata["description"],
        "Risk Score (0-100)": risk_score,
        "Threat Level": "🟢 Safe" if risk_score <= 20 else "🟡 Moderate Risk" if risk_score <= 50 else "🔴 High Risk"
    }

    print(json.dumps(report, indent=4))

# Run the analyzer
if __name__ == "__main__":
    user_url = input("Enter URL to analyze: ")
    analyze_url(user_url)
