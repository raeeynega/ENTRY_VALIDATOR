import requests
from datetime import datetime, timedelta
import os
import re
from dotenv import load_dotenv

load_dotenv()

class ValidationEngine:
    def __init__(self):
        self.api_url = os.getenv('REDCAP_API_URL')
        self.api_token = os.getenv('REDCAP_API_TOKEN')
        self.rules = []
        self.setup_default_rules()
    
    def setup_default_rules(self):
        """Configure your validation rules - CUSTOMIZE THESE!"""
        
        # Rule 1: Age must be between 0-120
        self.add_rule(
            field='age',
            validation_func=lambda x: 0 <= int(x) <= 120 if x and str(x).strip() else True,
            error_msg='Age out of valid range (0-120)',
            suggestion='Verify patient birth date in medical records',
            severity='Critical'
        )
        
        # Rule 2: Visit date cannot be in the future
        self.add_rule(
            field='visit_date',
            validation_func=lambda x: datetime.strptime(x, '%Y-%m-%d') <= datetime.now() if x else True,
            error_msg='Visit date cannot be in the future',
            suggestion='Correct to today\'s date or verify visit actually occurred',
            severity='Critical'
        )
        
        # Rule 3: Email format validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        self.add_rule(
            field='email',
            validation_func=lambda x: re.match(email_pattern, x) if x else True,
            error_msg='Invalid email format',
            suggestion='Enter email as name@domain.com',
            severity='Warning'
        )
        
        # Rule 4: Phone number format (US)
        phone_pattern = r'^\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})$'
        self.add_rule(
            field='phone',
            validation_func=lambda x: re.match(phone_pattern, x) if x else True,
            error_msg='Invalid phone number format',
            suggestion='Use format: (123) 456-7890 or 123-456-7890',
            severity='Warning'
        )
        
        # Rule 5: Quantity must be positive
        self.add_rule(
            field='quantity',
            validation_func=lambda x: float(x) > 0 if x and str(x).strip() else True,
            error_msg='Quantity must be greater than zero',
            suggestion='Enter a positive number',
            severity='Critical'
        )
        
        # Rule 6: Price must be positive
        self.add_rule(
            field='price',
            validation_func=lambda x: float(x) > 0 if x and str(x).strip() else True,
            error_msg='Price must be greater than zero',
            suggestion='Enter a positive amount',
            severity='Critical'
        )
        
        # ADD YOUR CUSTOM RULES HERE
        # self.add_rule(
        #     field='your_field',
        #     validation_func=lambda x: your_condition_here,
        #     error_msg='Your error message',
        #     suggestion='How to fix it',
        #     severity='Critical'  # or 'Warning' or 'Info'
        # )
    
    def add_rule(self, field, validation_func, error_msg, suggestion, severity='Warning'):
        """Add a validation rule with severity level"""
        self.rules.append({
            'field': field,
            'func': validation_func,
            'error_msg': error_msg,
            'suggestion': suggestion,
            'severity': severity
        })
    
    def fetch_record(self, record_id):
        """Fetch record from REDCap API"""
        if not self.api_token or self.api_token == 'your_api_token_here':
            print("⚠️  No valid API token found. Using mock data for testing.")
            return self.get_mock_record(record_id)
        
        payload = {
            'token': self.api_token,
            'content': 'record',
            'format': 'json',
            'type': 'flat',
            'records[0]': record_id
        }
        
        try:
            response = requests.post(self.api_url, data=payload)
            response.raise_for_status()
            data = response.json()
            return data[0] if data else None
        except Exception as e:
            print(f"Error fetching record {record_id}: {e}")
            return None
    
    def get_mock_record(self, record_id):
        """Return mock data for testing when no API token"""
        # This simulates what REDCap would return
        mock_records = {
            'REC-001': {
                'record_id': 'REC-001',
                'age': '25',
                'visit_date': '2026-02-24',
                'email': 'john@example.com',
                'phone': '555-123-4567',
                'quantity': '10',
                'price': '99.99'
            },
            'REC-002': {
                'record_id': 'REC-002',
                'age': '150',  # This will trigger error
                'visit_date': '2026-03-01',  # Future date - error
                'email': 'invalid-email',  # Error
                'phone': '12345',  # Error
                'quantity': '-5',  # Error
                'price': '-10.00'  # Error
            }
        }
        return mock_records.get(record_id, {
            'record_id': record_id,
            'age': '45',
            'visit_date': '2026-02-20',
            'email': 'test@example.com',
            'phone': '555-555-5555',
            'quantity': '5',
            'price': '50.00'
        })
    
    def fetch_user_info(self, record_id, timestamp=None):
        """Get user who entered the data from REDCap logs"""
        if not self.api_token or self.api_token == 'your_api_token_here':
            # Return mock user for testing
            return {
                'username': 'test_user',
                'device': 'Web Browser',
                'location': 'Test Location'
            }
        
        if not timestamp:
            timestamp = datetime.now().isoformat()
        
        # Parse timestamp if it's a string
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except:
                timestamp = datetime.now()
        
        payload = {
            'token': self.api_token,
            'content': 'log',
            'action': 'export',
            'format': 'json',
            'record': record_id,
            'logtype': 'record',
            'beginTime': (timestamp - timedelta(minutes=30)).isoformat(),
            'endTime': (timestamp + timedelta(minutes=30)).isoformat()
        }
        
        try:
            response = requests.post(self.api_url, data=payload)
            response.raise_for_status()
            logs = response.json()
            
            # Find the most recent relevant log
            for log in logs:
                if log.get('action') in ['Insert', 'Update']:
                    return {
                        'username': log.get('user', 'Unknown'),
                        'device': 'REDCap Web',
                        'location': '',
                        'timestamp': log.get('timestamp', '')
                    }
        except Exception as e:
            print(f"Error fetching user info: {e}")
        
        return {'username': 'Unknown', 'device': 'REDCap Web', 'location': ''}
    
    def validate_record(self, record_id, timestamp=None):
        """Validate a single record against all rules"""
        # Fetch the record
        record = self.fetch_record(record_id)
        if not record:
            print(f"⚠️  No record found for ID: {record_id}")
            return []
        
        # Get user info
        user_info = self.fetch_user_info(record_id, timestamp)
        
        errors = []
        for rule in self.rules:
            field = rule['field']
            if field in record:
                value = record[field]
                # Skip empty values
                if value is None or value == '':
                    continue
                    
                try:
                    # Apply validation rule
                    if not rule['func'](value):
                        error = {
                            'record_id': record_id,
                            'field_name': field,
                            'error_value': str(value),
                            'error_message': rule['error_msg'],
                            'suggested_correction': rule['suggestion'],
                            'entered_by': user_info.get('username', 'Unknown'),
                            'device_info': {
                                'device': user_info.get('device', 'Unknown'),
                                'location': user_info.get('location', '')
                            },
                            'severity': rule.get('severity', 'Warning'),
                            'status': 'Pending',
                            'timestamp': datetime.now().isoformat()
                        }
                        errors.append(error)
                        print(f"✅ Found error: {field} = {value} - {rule['error_msg']}")
                except ValueError as e:
                    print(f"⚠️  Value error validating {field}={value}: {e}")
                except Exception as e:
                    print(f"⚠️  Error validating {field}: {e}")
        
        return errors
    
    def validate_multiple_records(self, record_ids):
        """Validate multiple records at once"""
        all_errors = []
        for record_id in record_ids:
            errors = self.validate_record(record_id)
            all_errors.extend(errors)
        return all_errors