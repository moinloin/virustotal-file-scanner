import tkinter as tk
from tkinter import filedialog
import requests
import webbrowser

API_Key = 'KEY_HERE'

def FileUpload():
    file_path = filedialog.askopenfilename()
    if file_path:
        url = "https://www.virustotal.com/api/v3/files"
        files = {"file": (file_path.split("/")[-1], open(file_path, "rb"), "text/x-python")}
        headers = {"X-Apikey": API_Key}
        response = requests.post(url, files=files, headers=headers)
        if response.status_code == 200:
            response_json = response.json()
            analysis_id = response_json['data']['id']
            refresh_data(analysis_id)
        else:
            print(f"Error: {response.status_code} - {response.text}")

def FileData(id):
    url = f"https://www.virustotal.com/api/v3/analyses/{id}"
    headers = {"X-Apikey": API_Key}
    response = requests.get(url, headers=headers)
    stats_json = response.json()
    stats_malicious = stats_json.get("data", {}).get("attributes", {}).get("stats", {}).get("malicious")
    stats_suspicious = stats_json.get("data", {}).get("attributes", {}).get("stats", {}).get("suspicious")
    stats_undetected = stats_json.get("data", {}).get("attributes", {}).get("stats", {}).get("undetected")
    hash_value = stats_json.get("meta", {}).get("file_info", {}).get("sha256")

    display_stats_malicious.config(text=f"Malicious: {stats_malicious}")
    display_stats_suspicious.config(text=f"Suspicious: {stats_suspicious}")
    display_stats_undetected.config(text=f"Undetected: {stats_undetected}")
    display_hash.config(text=f"Hash: {hash_value}")
    display_url.config(text=f"URL VirusTotal: https://www.virustotal.com/gui/file/{hash_value}", cursor="hand2")
    display_url.bind("<Button-1>", lambda e: open_url(f"https://www.virustotal.com/gui/file/{hash_value}"))

def refresh_data(id):
    FileData(id)
    root.after(5000, lambda: refresh_data(id))

def open_url(url):
    webbrowser.open_new(url)

root = tk.Tk()
root.title("VirusTotal File Scanner")

upload_button = tk.Button(root, text="Upload File", command=FileUpload)
upload_button.pack(pady=10)

display_stats_malicious = tk.Label(root, text="")
display_stats_malicious.pack(pady=2, anchor=tk.W)

display_stats_suspicious = tk.Label(root, text="")
display_stats_suspicious.pack(pady=2, anchor=tk.W)

display_stats_undetected = tk.Label(root, text="")
display_stats_undetected.pack(pady=2, anchor=tk.W)

display_hash = tk.Label(root, text="")
display_hash.pack(pady=3, anchor=tk.W)

display_url = tk.Label(root, text="", cursor="hand2", fg="blue")
display_url.pack(pady=5)

root.mainloop()
