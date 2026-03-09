import sqlite3
import json
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import hashlib

load_dotenv()

class ValidationDatabase:
    def __init__(self):
        db_path = os.getenv('DATABASE_PATH', 'validation_results.db')
        
        # Check if database exists and create connection
        db_exists = os.path.exists(db_path)
        
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        
        # Create/update tables
        self.create_tables()
        
        if not db_exists:
            print(f"✅ Created new database: {db_path}")
        else:
            print(f"📂 Connected to existing database: {db_path}")
        
    def create_tables(self):
        """Create database tables if they don't exist"""
        cursor = self.conn.cursor()
        
        # Clean up any leftover temporary tables from failed migrations
        cursor.execute("DROP TABLE IF EXISTS validation_errors_new")
        
        # Check if the old table exists without new columns
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='validation_errors'")
        table_exists = cursor.fetchone() is not None
        
        if table_exists:
            # Check current columns
            cursor.execute("PRAGMA table_info(validation_errors)")
            columns = [column[1] for column in cursor.fetchall()]
            
            # If we're missing columns, do a full migration
            missing_columns = []
            for col in ['form_name', 'next_form', 'resolved_at', 'resolved_by', 'updated_at']:
                if col not in columns:
                    missing_columns.append(col)
            
            if missing_columns:
                print(f"🔄 Migrating database - adding columns: {missing_columns}")
                self._migrate_database(cursor, columns)
        else:
            # Create new table from scratch
            self._create_new_table(cursor)
        
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
    
    def _create_new_table(self, cursor):
        """Create a new validation_errors table with all columns"""
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
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                form_name TEXT,
                next_form TEXT,
                resolved_at TEXT,
                resolved_by TEXT,
                updated_at TEXT
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_record_field ON validation_errors(record_id, field_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_active_errors ON validation_errors(status, timestamp)')
        
        print("✅ Created new validation_errors table")
    
    def _migrate_database(self, cursor, existing_columns):
        """Safely migrate existing database to new schema"""
        
        # Drop the temporary table if it exists from a previous failed migration
        cursor.execute("DROP TABLE IF EXISTS validation_errors_new")
        
        # First, create a new table with the full schema
        cursor.execute('''
            CREATE TABLE validation_errors_new (
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
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                form_name TEXT,
                next_form TEXT,
                resolved_at TEXT,
                resolved_by TEXT,
                updated_at TEXT
            )
        ''')
        
        # Build the column list for copying
        col_list = []
        for col in ['id', 'record_id', 'field_name', 'error_value', 'error_message', 
                   'suggested_correction', 'entered_by', 'device_info', 'severity', 
                   'status', 'timestamp', 'resolved', 'resolution_notes', 'created_at']:
            if col in existing_columns:
                col_list.append(col)
        
        # Copy data from old table to new table
        if col_list:
            cols_str = ', '.join(col_list)
            try:
                cursor.execute(f'''
                    INSERT INTO validation_errors_new ({cols_str})
                    SELECT {cols_str} FROM validation_errors
                ''')
                print(f"✅ Copied data to new table")
            except Exception as e:
                print(f"⚠️ Error copying data: {e}")
        
        # Drop old table and rename new table
        cursor.execute('DROP TABLE IF EXISTS validation_errors')
        cursor.execute('ALTER TABLE validation_errors_new RENAME TO validation_errors')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_record_field ON validation_errors(record_id, field_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_active_errors ON validation_errors(status, timestamp)')
        
        print(f"✅ Database migration completed successfully")
    
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
        """
        Log a validation error - if error exists for same record and field, update it
        Returns: id of error
        """
        cursor = self.conn.cursor()
        
        # Check if there's already an active error for this record and field
        cursor.execute('''
            SELECT id, error_value, status FROM validation_errors 
            WHERE record_id = ? AND field_name = ? AND status IN ('Pending', 'Active')
            ORDER BY timestamp DESC LIMIT 1
        ''', (error_data['record_id'], error_data['field_name']))
        
        existing = cursor.fetchone()
        
        # Ensure device_info is properly formatted
        device_info = error_data.get('device_info', {})
        if isinstance(device_info, dict):
            device_info_json = json.dumps(device_info)
        else:
            device_info_json = json.dumps({'raw': str(device_info)})
        
        # Get form_name and next_form if they exist
        form_name = error_data.get('form_name', '')
        next_form = error_data.get('next_form', '')
        current_time = datetime.now().isoformat()
        
        if existing:
            # Error exists - update it
            error_id = existing[0]
            old_value = existing[1]
            
            # If the error value is the same, just update timestamp
            if old_value == error_data.get('error_value', ''):
                cursor.execute('''
                    UPDATE validation_errors 
                    SET timestamp = ?, updated_at = ?, device_info = ?, 
                        form_name = ?, next_form = ?, entered_by = ?
                    WHERE id = ?
                ''', (current_time, current_time, device_info_json, 
                      form_name, next_form, error_data.get('entered_by', 'Unknown'), error_id))
                print(f"🔄 Updated existing error: {error_data.get('field_name')} (ID: {error_id})")
            else:
                # Value changed - update with new value
                cursor.execute('''
                    UPDATE validation_errors 
                    SET error_value = ?, timestamp = ?, updated_at = ?, 
                        device_info = ?, form_name = ?, next_form = ?, 
                        entered_by = ?
                    WHERE id = ?
                ''', (
                    error_data.get('error_value', ''),
                    current_time,
                    current_time,
                    device_info_json,
                    form_name,
                    next_form,
                    error_data.get('entered_by', 'Unknown'),
                    error_id
                ))
                print(f"📝 Updated error value for: {error_data.get('field_name')} (ID: {error_id})")
            
            self.conn.commit()
            return error_id
        
        else:
            # No existing error - insert new one
            try:
                cursor.execute('''
                    INSERT INTO validation_errors 
                    (record_id, field_name, error_value, error_message, 
                     suggested_correction, entered_by, device_info, severity, 
                     status, timestamp, form_name, next_form, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    error_data['record_id'],
                    error_data['field_name'],
                    error_data.get('error_value', ''),
                    error_data['error_message'],
                    error_data.get('suggested_correction', ''),
                    error_data.get('entered_by', 'Unknown'),
                    device_info_json,
                    error_data.get('severity', 'Critical'),
                    error_data.get('status', 'Pending'),
                    current_time,
                    form_name,
                    next_form,
                    current_time,
                    current_time
                ))
                self.conn.commit()
                new_id = cursor.lastrowid
                print(f"✅ Logged new error: {error_data.get('field_name')} (ID: {new_id})")
                return new_id
            except Exception as e:
                print(f"❌ Error logging to database: {e}")
                return None
    
    def get_active_errors(self, include_resolved=False):
        """Get all unresolved errors"""
        try:
            cursor = self.conn.cursor()
            
            if include_resolved:
                # Get all errors
                cursor.execute('''
                    SELECT 
                        id, record_id, field_name, error_value, error_message,
                        suggested_correction, entered_by, device_info, severity, 
                        status, timestamp, form_name, next_form
                    FROM validation_errors 
                    ORDER BY datetime(timestamp) DESC
                ''')
            else:
                # Get only active/pending errors
                cursor.execute('''
                    SELECT 
                        id, record_id, field_name, error_value, error_message,
                        suggested_correction, entered_by, device_info, severity, 
                        status, timestamp, form_name, next_form
                    FROM validation_errors 
                    WHERE status IN ('Pending', 'Active')
                    ORDER BY datetime(timestamp) DESC
                ''')
            
            rows = cursor.fetchall()
            
            print(f"📊 Database query returned {len(rows)} rows")
            
            errors = []
            for row in rows:
                try:
                    # Safely parse device_info - handle empty or invalid JSON
                    device_info_str = row[7] if len(row) > 7 and row[7] else '{}'
                    device_info = {}
                    
                    if device_info_str and isinstance(device_info_str, str):
                        try:
                            # Try to parse as JSON
                            device_info = json.loads(device_info_str)
                        except json.JSONDecodeError:
                            # If not valid JSON, treat as plain string
                            device_info = {'raw': device_info_str[:50]}
                    elif device_info_str and isinstance(device_info_str, dict):
                        # Already a dict
                        device_info = device_info_str
                    
                    error = {
                        'id': row[0],
                        'record_id': row[1],
                        'field_name': row[2],
                        'error_value': row[3] if row[3] else '',
                        'error_message': row[4],
                        'suggested_correction': row[5] if row[5] else '',
                        'entered_by': row[6] if row[6] else 'Unknown',
                        'device': device_info.get('device', 'Unknown'),
                        'location': device_info.get('location', ''),
                        'severity': row[8] if len(row) > 8 and row[8] else 'Warning',
                        'status': row[9] if len(row) > 9 and row[9] else 'Pending',
                        'timestamp': row[10] if len(row) > 10 and row[10] else '',
                        'form_name': row[11] if len(row) > 11 else '',
                        'next_form': row[12] if len(row) > 12 else ''
                    }
                    errors.append(error)
                except Exception as e:
                    print(f"❌ Error parsing row {row[0] if len(row) > 0 else 'unknown'}: {e}")
                    continue
            
            print(f"✅ Successfully parsed {len(errors)} errors")
            return errors
            
        except Exception as e:
            print(f"❌ Database error in get_active_errors: {e}")
            import traceback
            traceback.print_exc()
            return []
    def get_unfilled_fields(self):
        """Get all fields that are required but left empty (including unselected radio buttons)"""
        try:
            cursor = self.conn.cursor()
            
            # This catches:
            # 1. Fields with 'required' in error message
            # 2. Fields with empty values that should have been selected
            # 3. Radio buttons that were never clicked
            cursor.execute('''
                SELECT record_id, field_name, form_name, timestamp, error_message
                FROM validation_errors 
                WHERE (
                    error_message LIKE '%required%' 
                    OR error_message LIKE '%must be selected%'
                    OR error_message LIKE '%choose%'
                    OR error_message LIKE '%select%'
                    OR (error_value = '' AND error_message LIKE '%required%')
                )
                AND status IN ('Pending', 'Active')
                ORDER BY datetime(timestamp) DESC
            ''')
            
            rows = cursor.fetchall()
            unfilled = []
            for row in rows:
                unfilled.append({
                    'record_id': row[0],
                    'field_name': row[1],
                    'form_name': row[2] if row[2] else 'Unknown Form',
                    'timestamp': row[3],
                    'error_message': row[4]
                })
            
            print(f"📊 Found {len(unfilled)} unfilled fields")
            return unfilled
        except Exception as e:
            print(f"❌ Error getting unfilled fields: {e}")
            return []
    def get_unfilled_fields_detailed(self):
            """Get ALL unfilled fields including unselected radio buttons"""
            cursor = self.conn.cursor()
             
            # List of field types that should never be empty
            cursor.execute('''
                SELECT 
                    record_id, 
                    field_name, 
                    form_name, 
                    timestamp,
                    CASE 
                        WHEN error_value = '' THEN 'No value provided'
                        ELSE error_message
                    END as reason
                FROM validation_errors 
                WHERE (
                    error_value = ''  -- Empty value
                    OR error_value IS NULL  -- NULL value
                    OR error_message LIKE '%required%'  -- Required field message
                    OR error_message LIKE '%select%'  -- Selection required
                    OR error_message LIKE '%choose%'  -- Choose an option
                )
                AND status IN ('Pending', 'Active')
                ORDER BY datetime(timestamp) DESC
            ''')
            
            rows = cursor.fetchall()
            unfilled = []
            for row in rows:
                unfilled.append({
                    'record_id': row[0],
                    'field_name': row[1],
                    'form_name': row[2] if row[2] else 'Unknown Form',
                    'timestamp': row[3],
                    'reason': row[4]
                })
            
            return unfilled
    def get_errors_by_record(self, record_id):
        """Get all errors for a specific record"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT 
                id, field_name, error_message, severity, status, timestamp, updated_at
            FROM validation_errors 
            WHERE record_id = ? AND status IN ('Pending', 'Active')
            ORDER BY datetime(timestamp) DESC
        ''', (record_id,))
        
        rows = cursor.fetchall()
        errors = []
        for row in rows:
            errors.append({
                'id': row[0],
                'field_name': row[1],
                'error_message': row[2],
                'severity': row[3],
                'status': row[4],
                'timestamp': row[5],
                'updated_at': row[6]
            })
        return errors
    
    def resolve_error(self, error_id, notes):
        """Mark an error as resolved"""
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE validation_errors 
            SET resolved = 1, status = 'Corrected', resolution_notes = ?,
                resolved_at = ?, resolved_by = ?
            WHERE id = ?
        ''', (notes, datetime.now().isoformat(), 'system', error_id))
        self.conn.commit()
        return cursor.rowcount > 0
    
    def dismiss_error(self, error_id):
        """Dismiss an error"""
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE validation_errors 
            SET status = 'Dismissed', resolved = 1,
                resolved_at = ?, resolved_by = ?
            WHERE id = ?
        ''', (datetime.now().isoformat(), 'system', error_id))
        self.conn.commit()
        return cursor.rowcount > 0
    
    def clear_all_pending(self, notes):
        """Mark all pending errors as resolved"""
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE validation_errors 
            SET resolved = 1, status = 'Corrected', resolution_notes = ?,
                resolved_at = ?, resolved_by = ?
            WHERE resolved = 0 OR status IN ('Pending', 'Active')
        ''', (notes, datetime.now().isoformat(), 'system'))
        self.conn.commit()
        return cursor.rowcount
    
    def cleanup_old_errors(self, days=30):
        """Archive or delete errors older than specified days"""
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        cursor = self.conn.cursor()
        
        # Instead of deleting, mark as archived
        cursor.execute('''
            UPDATE validation_errors 
            SET status = 'Archived' 
            WHERE datetime(timestamp) < datetime(?) 
            AND status IN ('Corrected', 'Dismissed')
        ''', (cutoff_date,))
        
        self.conn.commit()
        return cursor.rowcount
    
    def get_error_statistics(self):
        """Get statistics about errors"""
        cursor = self.conn.cursor()
        
        stats = {}
        
        # Total by severity
        cursor.execute('''
            SELECT severity, COUNT(*) as count 
            FROM validation_errors 
            WHERE status IN ('Pending', 'Active')
            GROUP BY severity
        ''')
        stats['by_severity'] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Total by field
        cursor.execute('''
            SELECT field_name, COUNT(*) as count 
            FROM validation_errors 
            WHERE status IN ('Pending', 'Active')
            GROUP BY field_name
            ORDER BY count DESC
            LIMIT 10
        ''')
        stats['top_fields'] = [{'field': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Total by record
        cursor.execute('''
            SELECT record_id, COUNT(*) as count 
            FROM validation_errors 
            WHERE status IN ('Pending', 'Active')
            GROUP BY record_id
            ORDER BY count DESC
            LIMIT 10
        ''')
        stats['top_records'] = [{'record': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Errors over time (last 7 days)
        cursor.execute('''
            SELECT date(timestamp) as day, COUNT(*) as count 
            FROM validation_errors 
            WHERE date(timestamp) >= date('now', '-7 days')
            GROUP BY date(timestamp)
            ORDER BY day
        ''')
        stats['over_time'] = [{'date': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        return stats