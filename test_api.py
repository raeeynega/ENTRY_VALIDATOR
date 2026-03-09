import requests
import json

api_url = "http://localhost/redcap/redcap_v14.1.6/API/"  # Adjust this to your actual API endpoint
token = "DCBB8A955E3C0DEB2D5093E275F6954E"  # Replace with your token

payload = {
    'token': token,
    'content': 'record',
    'format': 'json',
    'type': 'flat',
    'records[0]': '1'
}

print(f"Testing API at: {api_url}")
print(f"With token: {token[:5]}...{token[-5:]}")

try:
    response = requests.post(api_url, data=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text[:200]}")
except Exception as e:
    print(f"Error: {e}")