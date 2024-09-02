                                                                                                                                                  ----------       למי שרואה את זה , במידה והקובץ Anti Viru.py לא מראה את הקוד אלא מן שגיאה כלשהי, זה הקוד למשימת: אנטי וירוס לסריקת קבצים זדוניים!!!!!!! 
import requests
import json
import time

API_KEY = "Change the text here to your API key please !"

def scan_file(file_path):
    url = "https://www.virustotal.com/vtapi/v2/file/scan"
    files = {'file': (file_path, open(file_path, 'rb'))}
    params = {'apikey': API_KEY}
    
    response = requests.post(url, files=files, params=params)
    
    if response.status_code == 200:
        json_response = response.json()
        scan_id = json_response.get('scan_id')
        print(f"File uploaded successfully. Scan ID: {scan_id}")
        return scan_id
    else:
        print(f"Failed to upload file. Status Code: {response.status_code}")
        return None

def get_report(scan_id):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {'apikey': API_KEY, 'resource': scan_id}
    
    while True:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            report = response.json()
            if report.get('response_code') == 1:
                positives = report.get('positives')
                total = report.get('total')
                print(f"Scan finished. {positives}/{total} engines detected the file as malicious.")
                return report
            else:
                print("Scan still in progress, waiting 30 seconds...")
                time.sleep(30)
        else:
            print(f"Failed to retrieve report. Status Code: {response.status_code}")
            return None

def main():
    file_path = "path_to_your_file.exe" 
    scan_id = scan_file(file_path)
    
    if scan_id:
        report = get_report(scan_id)
        if report:
            print("Report:", json.dumps(report, indent=4))

if __name__ == "__main__":
    main()
