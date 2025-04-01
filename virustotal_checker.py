import requests
import json

# VirusTotal API Key
VIRUSTOTAL_API_KEY = "9c7fcc9fb15679dc6525c6c820887f4d8396171c11cdf3a8b181dbea05b08616"

def check_virustotal(url):
    """Check if the URL is flagged as malicious using VirusTotal API."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url}
    
    # Submit URL for scanning
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    if response.status_code != 200:
        return {"VirusTotal Report": "❌ API request failed"}
    
    try:
        response_data = response.json()
        analysis_id = response_data.get("data", {}).get("id")
        
        # Fetch analysis report
        if analysis_id:
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            report_response = requests.get(report_url, headers=headers)
            report_data = report_response.json()
            
            malicious_count = report_data.get("data", {}).get("attributes", {}).get("stats", {}).get("malicious", 0)
            
            if malicious_count > 0:
                return {"VirusTotal Report": f"⚠️ Detected as Malicious by {malicious_count} sources"}
            else:
                return {"VirusTotal Report": "✅ No threats detected"}
        
        return {"VirusTotal Report": "⚠️ Unexpected VirusTotal response format"}
    except json.JSONDecodeError:
        return {"VirusTotal Report": "❌ Error decoding API response"}

# Example Usage (if running this file directly)
if __name__ == "__main__":
    test_url = input("Enter URL to check: ")
    print(check_virustotal(test_url))
