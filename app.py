from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from database import ValidationDatabase
from validation_engine import ValidationEngine
import os
import functools
from dotenv import load_dotenv
from datetime import datetime, timedelta

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
            return redirect(url_for('dashboard'))
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
def dashboard_with_project():
    """Dashboard with project context"""
    # Get selected project from query string
    project = request.args.get('project', 'ibd')
    
    # Store project in session
    session['current_project'] = project
    
    # Get filter from query string (All, Critical, Warning, Info)
    severity_filter = request.args.get('filter', 'All')
    
    # Get all errors
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
        'active': len([e for e in all_errors if e.get('status', '').lower() == 'pending']),
        'records_affected': len(set([e.get('record_id') for e in all_errors])),
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
    errors = db.get_active_errors()
    return jsonify({'errors': errors})

@app.route('/redcap-webhook', methods=['POST'])
def redcap_webhook():
    """Endpoint for REDCap Data Entry Trigger (no login required)"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data received'}), 400
    
    record_id = data.get('record')
    
    # Validate the record
    errors = validator.validate_record(record_id)
    
    # Log all errors
    for error in errors:
        db.log_error(error)
    
    return jsonify({
        'status': 'processed',
        'record': record_id,
        'errors_found': len(errors)
    })

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
            'status': 'Pending',
            'timestamp': '2026-02-25 09:12'
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
            'status': 'Corrected',
            'timestamp': '2026-02-25 09:08'
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
            'status': 'Pending',
            'timestamp': '2026-02-25 08:55'
        },
        {
            'record_id': 'RC-004',
            'field_name': 'Expiry Date',
            'error_value': '30/02/2026',
            'error_message': 'Invalid date — February has no 30th',
            'suggested_correction': '28/02/2026',
            'entered_by': 'Tom Nguyen',
            'device_info': {'device': 'Scanner #1', 'location': 'Warehouse A'},
            'severity': 'Critical',
            'status': 'Pending',
            'timestamp': '2026-02-25 08:42'
        },
        {
            'record_id': 'RC-005',
            'field_name': 'Supplier Name',
            'error_value': 'Acmee Corp',
            'error_message': 'Possible typo in supplier name',
            'suggested_correction': 'Acme Corp',
            'entered_by': 'Sara Kim',
            'device_info': {'device': 'Desktop', 'location': 'Office'},
            'severity': 'Info',
            'status': 'Corrected',
            'timestamp': '2026-02-25 08:30'
        },
        {
            'record_id': 'RC-006',
            'field_name': 'Unit Price',
            'error_value': '-5.00',
            'error_message': 'Negative unit price detected',
            'suggested_correction': '5.00',
            'entered_by': 'James Carter',
            'device_info': {'device': 'Terminal #2', 'location': 'Floor 1'},
            'severity': 'Critical',
            'status': 'Dismissed',
            'timestamp': '2026-02-25 08:15'
        }
    ]
    
    for error in sample_errors:
        db.log_error(error)
    
    flash('Sample data loaded successfully', 'success')
    return redirect(url_for('dashboard_with_project', project=session.get('current_project', 'ibd')))

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    return render_template('profile.html', 
                         user=session.get('name'),
                         username=session.get('user'),
                         role=session.get('role'),
                         login_time=session.get('login_time'))

# ============= USER MANAGEMENT ROUTES =============

@app.route('/admin/users')
@admin_required
def manage_users():
    """Admin-only user management"""
    users = db.get_all_users()
    return render_template('users.html', users=users)

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

@app.route('/test-mock')
@login_required
def test_mock():
    """Test with mock data"""
    # Test with REC-002 which has multiple errors
    errors = validator.validate_record('REC-002')
    
    # Log to database
    for error in errors:
        db.log_error(error)
    
    flash('Test data validated and logged', 'success')
    return redirect(url_for('dashboard_with_project', project=session.get('current_project', 'ibd')))

@app.route('/clear-all', methods=['POST'])
@admin_required
def clear_all_errors():
    """Mark all errors as reviewed (admin only)"""
    notes = f"Batch cleared by admin: {session.get('name')}"
    count = db.clear_all_pending(notes)
    flash(f'{count} errors cleared successfully', 'success')
    return redirect(url_for('dashboard_with_project', project=session.get('current_project', 'ibd')))

if __name__ == '__main__':
    app.run(debug=True, port=5000)