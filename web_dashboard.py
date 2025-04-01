from flask import Flask, render_template, request
from pymongo import MongoClient
from datetime import datetime
from url_checker import analyze_url  # Import your URL checking function

app = Flask(__name__)

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["url_analysis_db"]
collection = db["reports"]

@app.route("/")
def home():
    """Display the latest reports from MongoDB."""
    reports = list(collection.find().sort("timestamp", -1))  # Fetch reports sorted by latest timestamp
    return render_template("dashboard.html", reports=reports)

@app.route("/analyze", methods=["POST"])
def analyze():
    """Manually trigger a new URL analysis."""
    user_url = request.form["url"]
    
    # Get analysis results
    results = analyze_url(user_url)
    results["url"] = user_url
    results["timestamp"] = datetime.utcnow()  # Store current timestamp

    # Insert into MongoDB
    collection.insert_one(results)

    return "URL Analysis Completed! <a href='/'>Go Back</a>"

if __name__ == "__main__":
    app.run(debug=True)
