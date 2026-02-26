import sqlite3
import json
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

class ValidationDatabase:
    def __init__(self):
        db_path = os.getenv('DATABASE_PATH', 'validation_results.db')
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.create_tables()
    
    def create_tables(self):
        """Create database tables if they don't exist"""
        cursor = self.conn.cursor()
        
        # Validation errors table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS validation_errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT NOT NULL,
                field_name TEXT NOT NULL,
                error_value TEXT,
                error_message TEXT NOT NULL,
                suggested_correction TEXT,
                entered_by TEXT,
                device_info TEXT,
                severity TEXT DEFAULT 'Critical',
                status TEXT DEFAULT 'Pending',
                timestamp TEXT NOT NULL,
                resolved BOOLEAN DEFAULT 0,
                resolution_notes TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Users table for authentication
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                active BOOLEAN DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_active TEXT,
                last_login TEXT
            )
        ''')
        
        self.conn.commit()
        
        # Initialize default users if table is empty
        self.init_default_users()
    
    def init_default_users(self):
        """Initialize default users if table is empty"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        
        if count == 0:
            # Add default users
            default_users = [
                ('admin', 'admin123', 'Administrator', 'admin'),
                ('supervisor', 'sup456', 'Supervisor', 'supervisor'),
                ('data_manager', 'data789', 'Data Manager', 'manager')
            ]
            
            for username, password, name, role in default_users:
                cursor.execute('''
                    INSERT INTO users (username, password, name, role, created_at, last_active)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (username, password, name, role, 
                      datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'Never'))
            
            self.conn.commit()
            print("✅ Default users created in database")
    
    # ============= USER MANAGEMENT METHODS =============
    
    def get_all_users(self):
        """Get all users from database"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT username, name, role, active, created_at, last_active 
            FROM users ORDER BY username
        ''')
        rows = cursor.fetchall()
        
        users = {}
        for row in rows:
            users[row[0]] = {
                'name': row[1],
                'role': row[2],
                'active': bool(row[3]),
                'created_at': row[4],
                'last_active': row[5] or 'Never'
            }
        return users
    
    def get_user(self, username):
        """Get a single user by username"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT username, password, name, role, active, created_at, last_active 
            FROM users WHERE username = ?
        ''', (username,))
        row = cursor.fetchone()
        
        if row:
            return {
                'username': row[0],
                'password': row[1],
                'name': row[2],
                'role': row[3],
                'active': bool(row[4]),
                'created_at': row[5],
                'last_active': row[6] or 'Never'
            }
        return None
    
    def add_user(self, username, password, name, role):
        """Add a new user to database"""
        cursor = self.conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, password, name, role, created_at, last_active)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, password, name, role, 
                  datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'Never'))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error adding user: {e}")
            return False
    
    def update_user(self, username, name, role, password=None):
        """Update an existing user"""
        cursor = self.conn.cursor()
        try:
            if password:
                cursor.execute('''
                    UPDATE users SET name = ?, role = ?, password = ? 
                    WHERE username = ?
                ''', (name, role, password, username))
            else:
                cursor.execute('''
                    UPDATE users SET name = ?, role = ? 
                    WHERE username = ?
                ''', (name, role, username))
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            print(f"Error updating user: {e}")
            return False
    
    def delete_user(self, username):
        """Delete a user from database"""
        cursor = self.conn.cursor()
        try:
            cursor.execute('DELETE FROM users WHERE username = ?', (username,))
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            print(f"Error deleting user: {e}")
            return False
    
    def update_last_active(self, username):
        """Update user's last active timestamp"""
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE users SET last_active = ? WHERE username = ?
        ''', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username))
        self.conn.commit()
    
    def authenticate_user(self, username, password):
        """Check if username/password is correct"""
        user = self.get_user(username)
        if user and user['password'] == password and user['active']:
            self.update_last_active(username)
            return user
        return None
    
    # ============= VALIDATION ERROR METHODS =============
    
    def log_error(self, error_data):
        """Log a validation error"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO validation_errors 
            (record_id, field_name, error_value, error_message, 
             suggested_correction, entered_by, device_info, severity, status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            error_data['record_id'],
            error_data['field_name'],
            error_data['error_value'],
            error_data['error_message'],
            error_data['suggested_correction'],
            error_data['entered_by'],
            json.dumps(error_data.get('device_info', {})),
            error_data.get('severity', 'Critical'),
            error_data.get('status', 'Pending'),
            error_data.get('timestamp', datetime.now().isoformat())
        ))
        self.conn.commit()
        return cursor.lastrowid
    
    def get_active_errors(self):
        """Get all unresolved errors"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM validation_errors 
            WHERE resolved = 0 
            ORDER BY datetime(timestamp) DESC
        ''')
        rows = cursor.fetchall()
        
        errors = []
        for row in rows:
            device_info = json.loads(row[7]) if row[7] else {}
            errors.append({
                'id': row[0],
                'record_id': row[1],
                'field_name': row[2],
                'error_value': row[3],
                'error_message': row[4],
                'suggested_correction': row[5],
                'entered_by': row[6],
                'device': device_info.get('device', ''),
                'location': device_info.get('location', ''),
                'severity': row[8],
                'status': row[9],
                'timestamp': row[10]
            })
        
        return errors
    
    def resolve_error(self, error_id, notes):
        """Mark an error as resolved"""
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE validation_errors 
            SET resolved = 1, status = 'Corrected', resolution_notes = ? 
            WHERE id = ?
        ''', (notes, error_id))
        self.conn.commit()
        return cursor.rowcount > 0
    
    def dismiss_error(self, error_id):
        """Dismiss an error"""
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE validation_errors 
            SET status = 'Dismissed', resolved = 1
            WHERE id = ?
        ''', (error_id,))
        self.conn.commit()
        return cursor.rowcount > 0
    
    def clear_all_pending(self, notes):
        """Mark all pending errors as resolved"""
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE validation_errors 
            SET resolved = 1, status = 'Corrected', resolution_notes = ? 
            WHERE resolved = 0
        ''', (notes,))
        self.conn.commit()
        return cursor.rowcount