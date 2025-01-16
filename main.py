import requests
import datetime
import csv
from google.cloud import storage
from flask import Request

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
BUCKET_NAME = "software_cve"
SOFTWARE_LIST = ["docker"]

# NVD APIから脆弱性情報取得
def fetch_vulnerabilities(software_name):
    pub_start_date = (datetime.datetime.utcnow() - datetime.timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    pub_end_date = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")

    params = {
        "keywordSearch": software_name,
        "resultsPerPage": 2000,
        "pubStartDate": pub_start_date,
        "pubEndDate": pub_end_date,
    }

    response = requests.get(API_URL, params=params)
    if response.status_code == 200:
        return response.json().get("vulnerabilities", [])
    else:
        print(f"Error fetching data for {software_name}: {response.status_code}")
        return []

# CSV出力
def write_to_csv(results, file_path):
    with open(file_path, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Software Name", "CVE ID", "Description", "Published Date"])
        for software_name, vulnerabilities in results.items():
            if vulnerabilities:
                for item in vulnerabilities:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "N/A")
                    descriptions = cve.get("descriptions", [])
                    description = descriptions[0].get("value") if descriptions else "N/A"
                    published_date = cve.get("published", "N/A")
                    writer.writerow([software_name, cve_id, description, published_date])
            else:
                writer.writerow([software_name, "No vulnerabilities found", "", ""])

# GCSへアップロード
def upload_to_gcs(bucket_name, source_file, destination_blob):
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob)
    blob.upload_from_filename(source_file)
    print(f"Uploaded {source_file} to gs://{bucket_name}/{destination_blob}")

# ✅ HTTPトリガー用のエントリポイント（修正済み）
def main(request: Request):
    results = {}
    for software in SOFTWARE_LIST:
        vulnerabilities = fetch_vulnerabilities(software)
        results[software] = vulnerabilities

    today = datetime.date.today().strftime("%Y%m%d")
    csv_file = f"/tmp/vulnerabilities_{today}.csv"

    write_to_csv(results, csv_file)
    upload_to_gcs(BUCKET_NAME, csv_file, f"results/vulnerabilities_{today}.csv")

    return f"Vulnerability data collected and uploaded to {BUCKET_NAME}."
