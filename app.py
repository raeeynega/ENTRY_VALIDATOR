from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from database import ValidationDatabase
from validation_engine import ValidationEngine
import os
import functools
import sqlite3
import json
from dotenv import load_dotenv
from datetime import datetime, timedelta
import re

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-this')
app.permanent_session_lifetime = timedelta(hours=8)  # Session expires after 8 hours

# Initialize components
db = ValidationDatabase()
validator = ValidationEngine()

def login_required(view):
    """Decorator to require login for routes"""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user' not in session:
            flash('Please log in to access the dashboard', 'info')
            return redirect(url_for('login', next=request.url))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    """Decorator for admin-only routes"""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user' not in session:
            flash('Please log in to access this page', 'info')
            return redirect(url_for('login', next=request.url))
        if session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard_with_project', project=session.get('current_project', 'ibd')))
        return view(**kwargs)
    return wrapped_view

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    # If already logged in, redirect to project selection
    if 'user' in session:
        return redirect(url_for('select_project'))
    
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'
        
        # Check credentials against database
        user = db.authenticate_user(username, password)
        
        if user:
            # Login successful
            session.permanent = remember
            session['user'] = username
            session['name'] = user['name']
            session['role'] = user['role']
            session['login_time'] = datetime.now().isoformat()
            session['current_project'] = 'ibd'  # Default project
            
            flash(f'Welcome back, {user["name"]}!', 'success')
            
            # Redirect to page user was trying to access
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('select_project'))
        else:
            error = 'Invalid username or password'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/select-project')
@login_required
def select_project():
    """Project selection page after login"""
    return render_template('select_project.html', 
                         user=session.get('name'))

@app.route('/dashboard')
@login_required
def dashboard_redirect():
    """Redirect old dashboard URL to new one with default project"""
    return redirect(url_for('dashboard_with_project', project=session.get('current_project', 'ibd')))

@app.route('/dashboard-with-project')
@login_required
def dashboard_with_project():
    """Dashboard with project context"""
    # Get selected project from query string
    project = request.args.get('project', session.get('current_project', 'ibd'))
    
    # Store project in session
    session['current_project'] = project
    
    # Get filter from query string (All, Critical, Warning, Info)
    severity_filter = request.args.get('filter', 'All')
    
    # Get all errors from database
    all_errors = db.get_active_errors()
    
    # Filter errors by project if your database has project field
    # For now, just pass all errors
    filtered_errors = all_errors
    
    # Apply severity filter
    if severity_filter != 'All':
        filtered_errors = [e for e in filtered_errors if e.get('severity', '').lower() == severity_filter.lower()]
    
    # Calculate stats
    stats = {
        'total': len(all_errors),
        'active': len([e for e in all_errors if e.get('status', '').lower() == 'active']),
        'records_affected': len(set([e.get('record_id') for e in all_errors if e.get('record_id')])),
        'critical': len([e for e in all_errors if e.get('severity', '').lower() == 'critical']),
        'warning': len([e for e in all_errors if e.get('severity', '').lower() == 'warning']),
        'info': len([e for e in all_errors if e.get('severity', '').lower() == 'info'])
    }
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Project display names
    project_names = {
        'ibd': 'IBD - Inflammatory Bowel Disease',
        'champs': 'CHAMPS - Child Health Surveillance',
        'pregnancy': 'Pregnancy Surveillance'
    }
    
    return render_template('dashboard.html', 
                         errors=filtered_errors,
                         all_errors_count=len(all_errors),
                         stats=stats,
                         current_filter=severity_filter,
                         now=now,
                         user=session.get('name'),
                         role=session.get('role'),
                         current_project=project,
                         project_name=project_names.get(project, 'Unknown Project'))

@app.route('/api/errors')
@login_required
def api_errors():
    """API endpoint for real-time updates"""
    try:
        app.logger.info("📊 Fetching active errors from database...")
        errors = db.get_active_errors()
        app.logger.info(f"📊 Found {len(errors)} errors")
        
        # Debug: log first error if any
        if errors:
            app.logger.info(f"📊 First error: {errors[0]}")
        
        return jsonify({
            'total': len(errors),
            'errors': errors
        })
    except Exception as e:
        app.logger.error(f"❌ Error in api_errors: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/redcap-webhook', methods=['POST'])
def redcap_webhook():
    """Endpoint for REDCap Data Entry Trigger - uses API to fetch actual data"""
    
    # Handle both JSON and form data
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()
    
    app.logger.info(f"📦 Trigger received: {data}")
    
    if not data:
        return jsonify({'error': 'No data received'}), 400
    
    record_id = data.get('record')
    if not record_id:
        return jsonify({'error': 'Record ID required'}), 400
    
    app.logger.info(f"📋 Trigger for record: {record_id}, instrument: {data.get('instrument')}")
    
    # DO NOT create a mock record - let the validation engine fetch via API
    # The ValidationEngine's fetch_record method will use the configured REDCap API
    
    try:
        # This will use the REDCap API to get the actual record data
        errors = validator.validate_record(record_id)
        app.logger.info(f"✅ Found {len(errors)} errors")
        
        # Log errors to database with context from the trigger
        for error in errors:
            error['form_name'] = data.get('instrument', 'unknown')
            error['entered_by'] = data.get('username', 'redcap_user')
            # Add completion status if useful
            complete_field = f"{data.get('instrument')}_complete"
            if complete_field in data:
                error['form_status'] = data.get(complete_field)
            db.log_error(error)
            app.logger.info(f"   → Logged: {error.get('field_name')} - {error.get('error_message')}")
        
        return jsonify({
            'status': 'processed',
            'record': record_id,
            'errors_found': len(errors)
        })
        
    except Exception as e:
        app.logger.error(f"❌ Validation error: {e}")
        return jsonify({'error': str(e)}), 500
# ============================================================================
# UPDATED ENDPOINT: Handle "Save & Go To Next Form" submissions
# Fully integrated with your 800+ validation rules
# ============================================================================

@app.route('/api/validate-on-submit', methods=['POST'])
def validate_on_submit():
    """
    Called when user clicks "Save & Go To Next Form" in REDCap
    Validates the form data using ALL 800+ ValidationEngine rules
    Returns validation results and determines if user can proceed
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data received'}), 400
    
    # Extract data from request
    record_id = data.get('record_id')
    current_form = data.get('current_form', 'unknown')
    next_form = data.get('next_form', 'unknown')
    username = data.get('username', 'Unknown')
    device = data.get('device', request.headers.get('User-Agent', 'Unknown'))
    form_data = data.get('form_data', {})
    
    if not record_id:
        return jsonify({'error': 'Record ID is required'}), 400
    
    app.logger.info(f"🔍 Validating record {record_id} for form {current_form} → {next_form}")
    app.logger.info(f"📋 Form data keys: {list(form_data.keys())}")
    
    # Create a mock record structure that ValidationEngine expects
    mock_record = {
        'record_id': record_id,
        **form_data  # Merge all form fields
    }
    
    # Store original fetch_record method
    original_fetch = validator.fetch_record
    
    # Override to use submitted data
    def mock_fetch(rid):
        if rid == record_id:
            return mock_record
        # For any other records (like cross-validation), fetch from API or return None
        return original_fetch(rid)
    
    validator.fetch_record = mock_fetch
    
    # Run validation using your existing 800+ rules
    # Run validation using your existing 800+ rules
    try:
        app.logger.info(f"🔍 Running validation engine for form: {current_form}...")
        # Pass the form name to validate only relevant fields
        errors = validator.validate_record(record_id, form_name=current_form)
        app.logger.info(f"✅ Validation complete. Found {len(errors)} errors")
    except Exception as e:
        app.logger.error(f"❌ Validation error: {e}")
        # Restore original method
        validator.fetch_record = original_fetch
        return jsonify({
            'status': 'error',
            'message': f'Validation error: {str(e)}',
            'can_proceed': True  # Allow proceed on error
        }), 200
    
    # Restore original method
    validator.fetch_record = original_fetch
    
    # Format errors for response and database
    formatted_errors = []
    critical_count = 0
    warning_count = 0
    info_count = 0
    
    for error in errors:
        # Count by severity
        severity = error.get('severity', 'Warning')
        if severity == 'Critical':
            critical_count += 1
        elif severity == 'Warning':
            warning_count += 1
        elif severity == 'Info':
            info_count += 1
        
        formatted_errors.append({
            'id': error.get('id', ''),
            'field': error.get('field_name', ''),
            'error': error.get('error_message', ''),
            'suggestion': error.get('suggested_correction', ''),
            'severity': severity,
            'value': error.get('error_value', ''),
            'record_id': record_id,
            'timestamp': error.get('timestamp', datetime.now().isoformat())
        })
    
    # Save errors to database
    if errors:
        app.logger.info(f"💾 Saving {len(errors)} errors to database...")
        for error in errors:
            # Add form context to error
            error['form_name'] = current_form
            error['next_form'] = next_form
            error['device_info'] = {'device': device, 'user': username}
            db.log_error(error)
        app.logger.info("✅ Errors saved to database")
    
    # Determine if user can proceed
    if critical_count > 0:
        # BLOCK navigation - must fix critical errors
        app.logger.warning(f"🚫 Blocking navigation: {critical_count} critical errors")
        return jsonify({
            'status': 'blocked',
            'can_proceed': False,
            'message': f'Found {critical_count} critical error(s). Please fix before proceeding.',
            'errors': formatted_errors,
            'total_errors': len(formatted_errors),
            'critical_count': critical_count,
            'warning_count': warning_count,
            'info_count': info_count,
            'next_form': next_form
        }), 422
    elif warning_count > 0:
        # ALLOW navigation but show warnings
        app.logger.info(f"⚠️ Allowing navigation with {warning_count} warnings")
        return jsonify({
            'status': 'warning',
            'can_proceed': True,
            'message': f'Found {warning_count} warning(s). You can proceed, but please review.',
            'errors': formatted_errors,
            'total_errors': len(formatted_errors),
            'critical_count': 0,
            'warning_count': warning_count,
            'info_count': info_count,
            'next_form': next_form
        }), 200
    else:
        # NO ERRORS - proceed normally
        app.logger.info("✅ No errors found, proceeding to next form")
        return jsonify({
            'status': 'success',
            'can_proceed': True,
            'message': 'Validation passed! Moving to next form.',
            'errors': formatted_errors if info_count > 0 else [],
            'total_errors': info_count,
            'critical_count': 0,
            'warning_count': 0,
            'info_count': info_count,
            'next_form': next_form
        }), 200
    

@app.route('/api/upload-csv', methods=['POST'])
@login_required
def upload_csv():
    """Upload and process CSV file"""
    if 'csv_file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['csv_file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.csv'):
        return jsonify({'error': 'File must be CSV'}), 400
    
    # Process CSV and add errors to database
    import csv
    import io
    
    stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
    csv_reader = csv.DictReader(stream)
    
    count = 0
    for row in csv_reader:
        # Map CSV columns to error data
        error_data = {
            'record_id': row.get('record_id', 'CSV-IMPORT'),
            'field_name': row.get('field_name', ''),
            'error_value': row.get('error_value', ''),
            'error_message': row.get('error_message', ''),
            'suggested_correction': row.get('suggestion', ''),
            'entered_by': session.get('name', 'CSV Import'),
            'severity': row.get('severity', 'Warning'),
            'status': 'Pending',
            'timestamp': datetime.now().isoformat()
        }
        
        if error_data['field_name'] and error_data['error_message']:
            db.log_error(error_data)
            count += 1
    
    return jsonify({'success': True, 'count': count})

@app.route('/api/export-csv')
@login_required
def export_csv():
    """Export errors as CSV"""
    import csv
    import io
    
    # Get selected IDs if any
    ids = request.args.get('ids', '')
    
    if ids:
        # Export selected errors
        id_list = [int(id) for id in ids.split(',')]
        placeholders = ','.join('?' * len(id_list))
        cursor = db.conn.cursor()
        cursor.execute(f'''
            SELECT record_id, field_name, error_value, error_message, 
                   suggested_correction, severity, status, timestamp
            FROM validation_errors 
            WHERE id IN ({placeholders})
        ''', id_list)
        rows = cursor.fetchall()
    else:
        # Export all active errors
        rows = db.get_active_errors(include_resolved=True)
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Record ID', 'Field', 'Error Value', 'Error Message', 
                     'Suggestion', 'Severity', 'Status', 'Timestamp'])
    
    for row in rows:
        writer.writerow([
            row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7]
        ])
    
    # Return as downloadable file
    from flask import make_response
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=errors_export.csv"
    response.headers["Content-type"] = "text/csv"
    return response
# ============================================================================
# NEW ENDPOINT: Manual validation trigger for testing
# ============================================================================

@app.route('/api/validate-record/<record_id>', methods=['POST'])
@login_required
def api_validate_record(record_id):
    """Manually trigger validation for a specific record"""
    # Get form data from request if provided
    data = request.get_json() or {}
    form_data = data.get('form_data', {})
    
    # Create mock record
    mock_record = {
        'record_id': record_id,
        **form_data
    }
    
    # Store original method
    original_fetch = validator.fetch_record
    
    # Override
    def mock_fetch(rid):
        if rid == record_id:
            return mock_record
        return original_fetch(rid)
    
    validator.fetch_record = mock_fetch
    
    # Validate
    try:
        errors = validator.validate_record(record_id)
    except Exception as e:
        validator.fetch_record = original_fetch
        return jsonify({'error': str(e)}), 500
    
    # Restore
    validator.fetch_record = original_fetch
    
    # Save to database
    for error in errors:
        error['device_info'] = {'device': 'Manual API', 'user': session.get('name', 'Unknown')}
        db.log_error(error)
    
    return jsonify({
        'record_id': record_id,
        'errors_found': len(errors),
        'errors': errors
    })

# ============================================================================
# NEW ENDPOINT: Get validation rules list
# ============================================================================

@app.route('/api/rules')
@login_required
def get_rules():
    """Get all validation rules"""
    rules = []
    for rule in validator.rules:
        rules.append({
            'field': rule.get('field'),
            'error_msg': rule.get('error_msg'),
            'suggestion': rule.get('suggestion'),
            'severity': rule.get('severity', 'Warning')
        })
    
    # Group by field
    rules_by_field = {}
    for rule in rules:
        field = rule['field']
        if field not in rules_by_field:
            rules_by_field[field] = []
        rules_by_field[field].append(rule)
    
    return jsonify({
        'total_rules': len(rules),
        'rules': rules,
        'rules_by_field': rules_by_field
    })

# ============================================================================
# NEW ENDPOINT: Get statistics by form
# ============================================================================

@app.route('/api/stats/by-form')
@login_required
def stats_by_form():
    """Get error statistics grouped by form"""
    conn = sqlite3.connect('validation_results.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT 
            form_name,
            COUNT(*) as error_count,
            SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical_count,
            SUM(CASE WHEN severity = 'Warning' THEN 1 ELSE 0 END) as warning_count,
            SUM(CASE WHEN severity = 'Info' THEN 1 ELSE 0 END) as info_count
        FROM validation_errors
        WHERE status = 'Active'
        GROUP BY form_name
        ORDER BY error_count DESC
    ''')
    
    rows = cursor.fetchall()
    conn.close()
    
    stats = []
    for row in rows:
        stats.append({
            'form_name': row[0] or 'Unknown',
            'error_count': row[1],
            'critical': row[2],
            'warning': row[3],
            'info': row[4]
        })
    
    return jsonify(stats)

@app.route('/resolve/<int:error_id>', methods=['POST'])
@login_required
def resolve(error_id):
    """Mark an error as resolved"""
    notes = request.form.get('notes', '')
    
    # Add who resolved it to notes
    notes = f"[Resolved by: {session.get('name')}] {notes}"
    
    if db.resolve_error(error_id, notes):
        flash('Error marked as corrected', 'success')
    else:
        flash('Error not found', 'error')
    
    return redirect(url_for('dashboard_with_project', project=session.get('current_project', 'ibd')))

@app.route('/dismiss/<int:error_id>', methods=['POST'])
@login_required
def dismiss(error_id):
    """Dismiss an error"""
    if db.dismiss_error(error_id):
        flash('Error dismissed', 'info')
    else:
        flash('Error not found', 'error')
    return redirect(url_for('dashboard_with_project', project=session.get('current_project', 'ibd')))

@app.route('/add-test-data')
@login_required
def add_test_data():
    """Add sample data for testing"""
    sample_errors = [
        {
            'record_id': 'RC-001',
            'field_name': 'Product Code',
            'error_value': 'RCP-441X',
            'error_message': 'Invalid product code format',
            'suggested_correction': 'RCP-441X',
            'entered_by': 'Maria Lopez',
            'device_info': {'device': 'Scanner #3', 'location': 'Warehouse B'},
            'severity': 'Critical',
            'status': 'Active',
            'timestamp': (datetime.now() - timedelta(minutes=30)).isoformat()
        },
        {
            'record_id': 'RC-002',
            'field_name': 'Quantity',
            'error_value': '10000',
            'error_message': 'Quantity exceeds maximum threshold (999)',
            'suggested_correction': '100',
            'entered_by': 'James Carter',
            'device_info': {'device': 'Terminal #7', 'location': 'Floor 2'},
            'severity': 'Critical',
            'status': 'Active',
            'timestamp': (datetime.now() - timedelta(minutes=25)).isoformat()
        },
        {
            'record_id': 'RC-003',
            'field_name': 'Batch Number',
            'error_value': 'BT-2026-0',
            'error_message': 'Incomplete batch number',
            'suggested_correction': 'BT-2026-001',
            'entered_by': 'Aisha Patel',
            'device_info': {'device': 'Mobile App', 'location': 'iOS'},
            'severity': 'Warning',
            'status': 'Active',
            'timestamp': (datetime.now() - timedelta(minutes=20)).isoformat()
        }
    ]
    
    for error in sample_errors:
        db.log_error(error)
    
    flash('Sample data loaded successfully', 'success')
    return redirect(url_for('dashboard_with_project', project=session.get('current_project', 'ibd')))

@app.route('/test-mock')
@login_required
def test_mock():
    """Test with mock data from validation_engine"""
    # Test with REC-002 which has multiple errors
    errors = validator.validate_record('REC-002')
    
    # Log to database
    for error in errors:
        db.log_error(error)
    
    flash(f'Test data validated. Found {len(errors)} errors.', 'success')
    return redirect(url_for('dashboard_with_project', project=session.get('current_project', 'ibd')))

@app.route('/test-champs')
@login_required
def test_champs():
    """Test with CHAMPS-specific mock data"""
    # Create a mock record with CHAMPS fields
    mock_record = {
        'record_id': 'CHAMPS-001',
        'champs_id_ps': '12345678',  # Only 8 digits - should trigger Rule 1
        'versionofdataspecification': '2.0.0',  # Wrong version - Rule 2
        'alt_mom_id_reg': 'A' * 60,  # Too long - Rule 3
        'phone_primary': '555-123-4567',  # Has dashes - Rules 4 & 5
        'address_primary': '',  # Empty - Rule 6 (Critical)
        'catchment_idreg': '5',  # Invalid - Rule 7
        'date_dob_mom': '2026-01-01',  # Future date - Rule 64
        'vocation': 'INVALID',  # Invalid - Rule 69
    }
    
    # Store original method
    original_fetch = validator.fetch_record
    
    # Override
    def mock_fetch(rid):
        if rid == 'CHAMPS-001':
            return mock_record
        return original_fetch(rid)
    
    validator.fetch_record = mock_fetch
    
    # Validate
    errors = validator.validate_record('CHAMPS-001')
    
    # Restore
    validator.fetch_record = original_fetch
    
    # Log errors
    for error in errors:
        error['device_info'] = {'device': 'CHAMPS Test', 'user': session.get('name', 'Unknown')}
        db.log_error(error)
    
    flash(f'CHAMPS test complete. Found {len(errors)} errors.', 'success')
    return redirect(url_for('dashboard_with_project', project=session.get('current_project', 'ibd')))

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    return render_template('profile.html', 
                         user=session.get('name'),
                         username=session.get('user'),
                         role=session.get('role'),
                         login_time=session.get('login_time'),
                         current_project=session.get('current_project', 'ibd'))

# ============= USER MANAGEMENT ROUTES =============

@app.route('/admin/users')
@admin_required
def manage_users():
    """Admin-only user management"""
    users = db.get_all_users()
    return render_template('users.html', users=users, current_project=session.get('current_project', 'ibd'))

@app.route('/add-user', methods=['POST'])
@admin_required
def add_user():
    """Add a new user"""
    username = request.form.get('username', '').strip()
    name = request.form.get('name', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'manager')
    
    # Validation
    if not username or not name or not password:
        flash('All fields are required', 'error')
        return redirect(url_for('manage_users'))
    
    # Check if user exists
    if db.get_user(username):
        flash(f'Username "{username}" already exists', 'error')
        return redirect(url_for('manage_users'))
    
    # Add user to database
    if db.add_user(username, password, name, role):
        flash(f'User "{username}" created successfully', 'success')
    else:
        flash('Error creating user', 'error')
    
    return redirect(url_for('manage_users'))

@app.route('/edit-user/<username>', methods=['POST'])
@admin_required
def edit_user(username):
    """Edit an existing user"""
    name = request.form.get('name', '').strip()
    role = request.form.get('role', 'manager')
    new_password = request.form.get('password', '')
    
    # Update user
    if db.update_user(username, name, role, new_password if new_password else None):
        flash(f'User "{username}" updated successfully', 'success')
    else:
        flash('User not found', 'error')
    
    return redirect(url_for('manage_users'))

@app.route('/delete-user/<username>', methods=['POST'])
@admin_required
def delete_user(username):
    """Delete a user"""
    # Prevent deleting yourself
    if username == session.get('user'):
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('manage_users'))
    
    if db.delete_user(username):
        flash(f'User "{username}" deleted successfully', 'success')
    else:
        flash('User not found', 'error')
    
    return redirect(url_for('manage_users'))

@app.route('/reset-password/<username>', methods=['POST'])
@admin_required
def reset_password(username):
    """Reset a user's password"""
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not new_password:
        flash('Password is required', 'error')
        return redirect(url_for('manage_users'))
    
    if new_password != confirm_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('manage_users'))
    
    # Get user to preserve other fields
    user = db.get_user(username)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('manage_users'))
    
    # Update password
    if db.update_user(username, user['name'], user['role'], new_password):
        flash(f'Password reset for "{username}" successfully', 'success')
    else:
        flash('Error resetting password', 'error')
    
    return redirect(url_for('manage_users'))

@app.route('/get-user/<username>')
@admin_required
def get_user(username):
    """Get user data for editing (AJAX)"""
    user = db.get_user(username)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'username': user['username'],
        'name': user['name'],
        'role': user['role']
    })

@app.route('/test-validation/<record_id>')
@login_required
def test_validation(record_id):
    """Test validation on a specific record"""
    errors = validator.validate_record(record_id)
    
    # Log errors to database
    for error in errors:
        db.log_error(error)
    
    return jsonify({
        'record_id': record_id,
        'errors_found': len(errors),
        'errors': errors
    })

@app.route('/clear-all', methods=['POST'])
@admin_required
def clear_all_errors():
    """Mark all errors as reviewed (admin only)"""
    notes = f"Batch cleared by admin: {session.get('name')}"
    count = db.clear_all_pending(notes)
    flash(f'{count} errors cleared successfully', 'success')
    return redirect(url_for('dashboard_with_project', project=session.get('current_project', 'ibd')))

@app.route('/bulk-resolve', methods=['POST'])
@admin_required
def bulk_resolve():
    """Resolve multiple errors at once"""
    error_ids = request.form.getlist('error_ids')
    notes = request.form.get('notes', 'Bulk resolve')
    
    if not error_ids:
        flash('No errors selected', 'warning')
        return redirect(url_for('dashboard_with_project', project=session.get('current_project', 'ibd')))
    
    count = 0
    for error_id in error_ids:
        try:
            error_id = int(error_id)
            if db.resolve_error(error_id, f"{notes} [Bulk by: {session.get('name')}]"):
                count += 1
        except:
            pass
    
    flash(f'{count} errors resolved successfully', 'success')
    return redirect(url_for('dashboard_with_project', project=session.get('current_project', 'ibd')))

#@app.errorhandler(404)
#def page_not_found(e):
#    """Handle 404 errors"""
#    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors"""
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Ensure database is initialized
    try:
        # Initialize validation_results.db if needed
        conn = sqlite3.connect('validation_results.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS validation_errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                error_id TEXT,
                record_id TEXT,
                field_name TEXT,
                error_value TEXT,
                error_message TEXT,
                suggested_correction TEXT,
                entered_by TEXT,
                device_info TEXT,
                severity TEXT,
                status TEXT DEFAULT 'Active',
                timestamp TEXT,
                form_name TEXT,
                next_form TEXT,
                resolved_notes TEXT,
                resolved_at TEXT,
                resolved_by TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS validation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                error_id INTEGER,
                action TEXT,
                action_by TEXT,
                action_notes TEXT,
                action_time TEXT,
                FOREIGN KEY (error_id) REFERENCES validation_errors (id)
            )
        ''')
        conn.commit()
        conn.close()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"⚠️ Database initialization warning: {e}")
    
    print("=" * 50)
    print("🚀 REDCap Validation System")
    print(f"🔗 Dashboard URL: http://127.0.0.1:5000")
    print(f"🔗 Validation API: http://127.0.0.1:5000/api/validate-on-submit")
    print("=" * 50)
    
    app.run(debug=True, port=5000)