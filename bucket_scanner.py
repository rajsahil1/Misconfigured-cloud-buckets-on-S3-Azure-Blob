import requests
import argparse
import json
from urllib.parse import urlparse
import boto3
from botocore.exceptions import ClientError
from azure.storage.blob import BlobServiceClient, ContainerClient

def check_http_access(url):
    """Check if URL is reachable and allows content listing."""
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            # Simple check if listing or index page present
            if '<ListBucketResult' in response.text or 'Index of' in response.text:
                return 'Public List Access'
            else:
                return 'Public Access (No Listing)'
        elif response.status_code == 403:
            return 'Access Denied (Private)'
        elif response.status_code == 404:
            return 'Not Found'
        else:
            return f'HTTP {response.status_code}'
    except Exception as e:
        return f'Error: {e}'

import requests

def check_s3_bucket(bucket_name):
    url = f"https://{bucket_name}.s3.amazonaws.com/"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            if '<ListBucketResult' in response.text or 'Index of' in response.text:
                return "Public List Access"
            else:
                return "Public Access (No Listing)"
        elif response.status_code == 403:
            return "Access Denied (Private)"
        elif response.status_code == 404:
            return "Not Found"
        else:
            return f"HTTP {response.status_code}"
    except Exception as e:
        return f"Error: {e}"


def check_azure_blob(container_url):
    """Check Azure Blob container list access (simplified)."""
    try:
        container = ContainerClient.from_container_url(container_url)
        blobs = container.list_blobs()
        # Try fetching some blobs
        for _ in blobs:
            return 'Public List Access'
        return 'Public Access (No Blobs)'
    except Exception as e:
        return f'Error: {e}'

def analyze_url(url):
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    if 's3.amazonaws.com' in hostname or hostname.endswith('.s3.amazonaws.com'):
        # Extract bucket name
        if hostname.endswith('.s3.amazonaws.com'):
            bucket_name = hostname.split('.')[0]
        else:
            bucket_name = parsed.path.strip('/').split('/')
        status = check_s3_bucket(bucket_name)
    elif 'blob.core.windows.net' in hostname:
        status = check_azure_blob(url)
    else:
        status = check_http_access(url)
    return status

def main(input_file, output_file):
    results = {}
    with open(input_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    print(f"Scanning {len(urls)} URLs...")
    for url in urls:
        status = analyze_url(url)
        print(f"{url} --> {status}")
        results[url] = status
    # Save report
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"Scan results saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cloud Storage Bucket Misconfiguration Scanner")
    parser.add_argument("input", help="Path to input file containing storage URLs")
    parser.add_argument("output", help="Path to output JSON report file")
    args = parser.parse_args()

    main(args.input, args.output)
