import schedule
import time
from pymongo import MongoClient
from url_checker import analyze_url  # Import your analysis function

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["url_analysis_db"]
collection = db["reports"]

def scheduled_url_scan():
    """Fetch URLs from MongoDB and analyze them periodically."""
    urls_to_check = collection.distinct("url")  # Get unique URLs from DB

    for url in urls_to_check:
        print(f"🔄 Running scheduled check for {url}")
        results = analyze_url(url)
        results["url"] = url
        results["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")

        # Save updated results in MongoDB
        collection.insert_one(results)
        print(f"✅ Report for {url} updated in database")

# Schedule the job to run every hour
schedule.every(1).hour.do(scheduled_url_scan)

print("⏳ Scheduled monitoring started...")
while True:
    schedule.run_pending()
    time.sleep(60)  # Check every minute if the schedule needs to run
