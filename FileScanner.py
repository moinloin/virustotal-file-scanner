import sys
import json
import requests
import argparse

API_Key = ''

parser = argparse.ArgumentParser(description='File Scanner using VirusTotal')
parser.add_argument('-f', type=str, help='Add File to scan', required=True)
args = parser.parse_args()
fileInput = args.f

def FileUpload(file):
    global analysis_id
    url = "https://www.virustotal.com/api/v3/files"
    files = { "file": (file, open(file, "rb"), "text/x-python") }
    headers = {
        "X-Apikey": API_Key
    }
    response = requests.post(url, files=files, headers=headers)
    if response.status_code == 200:
        response_json = response.json()
        analysis_id = response_json['data']['id']
        return analysis_id
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

def FileData(id):
    global stats
    global hash

    url = f"https://www.virustotal.com/api/v3/analyses/{id}"
    header = {
        "X-Apikey": API_Key
    }
    response = requests.get(url, headers=header)
    stats_json = response.json()
    stats = {
        "id": stats_json.get("data",{}).get("id"),
        "stats": stats_json.get("data", {}).get("attributes",{}).get("stats"),
    }
    hash = stats_json.get("meta", {}).get("file_info", {}).get("sha256")
    print(stats)
    print("Hash: ", hash)
    print(f"URL: https://www.virustotal.com/gui/file/{hash}")

FileUpload(fileInput)
FileData(analysis_id)
