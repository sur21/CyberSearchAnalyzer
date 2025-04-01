import requests
import json
import socket
import ssl
import whois
from datetime import datetime
from pymongo import MongoClient

# ✅ MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")  # Change this if using a remote MongoDB
db = client["url_analysis_db"]
collection = db["reports"]

# ✅ API Keys
SERP_API_KEY = "e08797ee6e7729658fa9713c67095463af68aea4227b0d388f5f2947ba8aaaae"
VIRUSTOTAL_API_KEY = "9c7fcc9fb15679dc6525c6c820887f4d8396171c11cdf3a8b181dbea05b08616"

# 🔒 1. SSL Certificate Check
def check_ssl_certificate(url):
    try:
        hostname = url.split("//")[-1].split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return "✅ Valid SSL Certificate" if cert else "⚠️ No SSL Certificate Found"
    except:
        return "❌ SSL Certificate Check Failed"

# 🌍 2. Domain Age Check
def check_domain_age(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return f"🌍 {age_days} days old" if age_days > 365 else "⚠️ Recently Registered Domain"
        return "❌ Domain Age Not Found"
    except:
        return "❌ Failed to Retrieve Domain Age"

# 🌐 3. WHOIS Information
def check_whois_info(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        domain_info = whois.whois(domain)
        registrar = domain_info.registrar or "Unknown"
        return f"🌍 Registered with {registrar}"
    except:
        return "❌ WHOIS Lookup Failed"

# 🚦 4. Phishing Database Check (OpenPhish)
def check_openphish(url):
    try:
        response = requests.get("https://openphish.com/feed.txt", timeout=10)
        phishing_sites = response.text.split("\n")
        return "⚠️ URL Found in OpenPhish Database" if url in phishing_sites else "✅ No phishing records found"
    except:
        return "❌ Failed to fetch phishing data"

# 🔍 5. VirusTotal Check
def check_virustotal(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    params = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)
    
    if response.status_code != 200:
        return "❌ VirusTotal API request failed"

    try:
        data = response.json()
        if "data" in data and "attributes" in data["data"]:
            malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            return f"⚠️ Detected as Malicious by {malicious_count} sources" if malicious_count > 0 else "✅ No threats detected"
        return "⚠️ Unexpected VirusTotal response format"
    except json.JSONDecodeError:
        return "❌ Error decoding VirusTotal API response"

# 🔎 Main URL Analysis Function
def analyze_url(user_url):
    report = {
        "url": user_url,
        "ssl_status": check_ssl_certificate(user_url),
        "domain_age": check_domain_age(user_url),
        "whois_info": check_whois_info(user_url),
        "phishing_status": check_openphish(user_url),
        "virustotal_report": check_virustotal(user_url),
        "timestamp": datetime.now()
    }

    # ✅ Save Report to MongoDB
    collection.insert_one(report)

    return report

# 🚀 Execute Script
if __name__ == "__main__":
    user_url = input("Enter the URL to check: ")
    result = analyze_url(user_url)

    print("\n📊 **Final Security Report Stored in Database:**")
    for key, value in result.items():
        print(f"{key}: {value}")






