import requests
import json

# Create a session to maintain cookies
session = requests.Session()

# Step 1: Login first
print("Logging in...")
login_data = {
    'username': 'admin',
    'password': 'admin123'
}
login_response = session.post('http://127.0.0.1:5000/login', data=login_data)
print(f"Login status: {login_response.status_code}")

if login_response.status_code != 200:
    print("❌ Login failed!")
    exit(1)

# Step 2: Check dashboard before
print("\nChecking dashboard before...")
before_response = session.get('http://127.0.0.1:5000/api/errors')
if before_response.status_code == 200:
    before_data = before_response.json()
    print(f"Errors before: {before_data.get('total', 0)}")
else:
    print(f"❌ Failed to get errors: {before_response.status_code}")
    before_data = {'total': 0}

# Step 3: Trigger webhook
print("\nTriggering webhook...")
webhook_data = {
    'record': '1',
    'instrument': 'maternal_registration_form',
    'username': 'site_admin'
}
webhook_response = session.post('http://127.0.0.1:5000/redcap-webhook', data=webhook_data)
print(f"Webhook status: {webhook_response.status_code}")
try:
    print(f"Webhook response: {webhook_response.json()}")
except:
    print(f"Webhook response text: {webhook_response.text}")

# Step 4: Check dashboard after
print("\nChecking dashboard after...")
after_response = session.get('http://127.0.0.1:5000/api/errors')
if after_response.status_code == 200:
    after_data = after_response.json()
    print(f"Errors after: {after_data.get('total', 0)}")
    
    # Show the errors
    if after_data.get('errors'):
        print("\n📋 Errors found:")
        for error in after_data['errors']:
            print(f"  • {error.get('field_name')}: {error.get('error_message')} ({error.get('severity')})")
    else:
        print("No errors found in database")
else:
    print(f"❌ Failed to get errors: {after_response.status_code}")