import boto3
import gzip
import io
import pandas as pd
from config import AWS_REGION, S3_BUCKET_NAME

# VPC Flow Log ke 14 fields
FIELDS = [
    'version', 'account_id', 'interface_id',
    'srcaddr', 'dstaddr', 'srcport', 'dstport',
    'protocol', 'packets', 'bytes',
    'start', 'end', 'action', 'log_status'
]

def get_log_files():
    """S3 se latest log files ki list lao"""
    print(f"[*] Connecting to S3 bucket: {S3_BUCKET_NAME}")
    s3 = boto3.client('s3', region_name=AWS_REGION)

    try:
        response = s3.list_objects_v2(Bucket=S3_BUCKET_NAME)

        if 'Contents' not in response:
            print("[!] Bucket empty hai — logs abhi tak nahi aaye")
            print("[!] 15-20 minutes wait karo aur dobara try karo")
            return []

        # Latest 5 files lo
        files = sorted(
            response['Contents'],
            key=lambda x: x['LastModified'],
            reverse=True
        )[:5]

        print(f"[+] {len(files)} log files mili")
        return [f['Key'] for f in files]

    except Exception as e:
        print(f"[ERROR] S3 connect nahi hua: {e}")
        return []

def parse_single_log(s3_client, file_key):
    """Ek log file download karke parse karo"""
    try:
        obj = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=file_key)
        content = obj['Body'].read()

        # Gzip decompress karo
        if file_key.endswith('.gz'):
            with gzip.GzipFile(fileobj=io.BytesIO(content)) as f:
                content = f.read().decode('utf-8')
        else:
            content = content.decode('utf-8')

        # Lines parse karo
        lines = []
        for line in content.strip().split('\n'):
            if line and not line.startswith('#'):
                parts = line.split()
                if len(parts) == 14:
                    lines.append(parts)

        if not lines:
            return None

        df = pd.DataFrame(lines, columns=FIELDS)
        return df

    except Exception as e:
        print(f"[ERROR] File parse nahi hui {file_key}: {e}")
        return None

def clean_dataframe(df):
    """DataFrame ko clean aur useable banao"""
    # Numeric columns convert karo
    numeric_cols = ['srcport', 'dstport', 'packets', 'bytes', 'start', 'end']
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    # Timestamp banao
    df['timestamp'] = pd.to_datetime(df['start'], unit='s', errors='coerce')

    # REJECT traffic alag karo
    df['is_rejected'] = df['action'] == 'REJECT'

    # Invalid rows hatao
    df = df.dropna(subset=['srcaddr', 'dstaddr', 'srcport', 'dstport'])

    # '-' values hatao (AWS inhe missing data ke liye use karta hai)
    df = df[df['srcaddr'] != '-']
    df = df[df['dstaddr'] != '-']

    return df

def fetch_latest_logs():
    """Main function — S3 se logs fetch karo aur clean DataFrame return karo"""
    print("\n" + "="*50)
    print("  NetGuard AI — Log Collector")
    print("="*50)

    s3 = boto3.client('s3', region_name=AWS_REGION)
    file_keys = get_log_files()

    if not file_keys:
        return None

    # Saari files parse karo
    all_dfs = []
    for key in file_keys:
        print(f"[*] Parsing: {key.split('/')[-1]}")
        df = parse_single_log(s3, key)
        if df is not None:
            all_dfs.append(df)

    if not all_dfs:
        print("[!] Koi valid log data nahi mila")
        return None

    # Sab combine karo
    combined = pd.concat(all_dfs, ignore_index=True)
    cleaned = clean_dataframe(combined)

    print(f"\n[+] Total log entries: {len(cleaned)}")
    print(f"[+] Unique source IPs: {cleaned['srcaddr'].nunique()}")
    print(f"[+] ACCEPT traffic: {(cleaned['action']=='ACCEPT').sum()}")
    print(f"[+] REJECT traffic: {(cleaned['action']=='REJECT').sum()}")
    print(f"\n--- Sample Data ---")
    print(cleaned[['srcaddr', 'dstaddr', 'srcport', 'dstport', 'action']].head())
    print("\n✅ Logs ready for analysis!")

    return cleaned

# Test karne ke liye
if __name__ == "__main__":
    df = fetch_latest_logs()
    