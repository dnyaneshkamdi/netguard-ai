import os
from dotenv import load_dotenv

# .env file se saari values load karo
load_dotenv()

# AWS Settings
AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "netguard-logs-dnyanesh")

# OpenAI Settings
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# Slack Settings
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

# Detection Settings
LOG_FETCH_INTERVAL = 60      # har 60 seconds mein logs check karo
ANOMALY_THRESHOLD = 0.05     # 5% traffic ko suspicious maano

print("✅ Config loaded successfully!")
print(f"   Region: {AWS_REGION}")
print(f"   Bucket: {S3_BUCKET_NAME}")