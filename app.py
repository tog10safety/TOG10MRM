# app.py
from flask import send_file, send_from_directory
import io
from flask import make_response
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import re
import html
from functools import wraps
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename

import os

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')

# FORCE PostgreSQL on Render - Remove all MySQL references
database_url = os.environ.get('DATABASE_URL')

if database_url:
    # Replace postgres:// with postgresql:// for SQLAlchemy
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    print(f"Using PostgreSQL: {database_url.split('@')[1] if '@' in database_url else 'Database configured'}")
else:
    # On Render, we MUST have DATABASE_URL
    raise ValueError("DATABASE_URL environment variable is required")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Security configurations
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800
)

# File upload configurations
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), "uploads")
app.config['SIGNATURE_FOLDER'] = os.path.join(os.getcwd(), "signatures")
app.config['LOGO_FOLDER'] = os.path.join(os.getcwd(), "static", "unit_logos")

db = SQLAlchemy(app)
csrf = CSRFProtect()
csrf.init_app(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Ensure upload folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['SIGNATURE_FOLDER'], exist_ok=True)
os.makedirs(app.config['LOGO_FOLDER'], exist_ok=True)

# User model - Optimized for MySQL


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True,
                         nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # CHANGED: Convert Enum to String for PostgreSQL compatibility
    authority = db.Column(db.String(20), nullable=False, default='Creator')
    category = db.Column(db.String(50), nullable=False)
    
    rank = db.Column(db.String(50))
    designation = db.Column(db.String(100))
    first_name = db.Column(db.String(100), nullable=False)
    middle_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100), nullable=False)
    serial_number = db.Column(db.String(50), nullable=False, unique=True)
    branch_of_service = db.Column(db.String(100), nullable=False)
    unit = db.Column(db.String(100), nullable=False, index=True)
    contact_number = db.Column(db.String(20))
    signature_filename = db.Column(db.String(200))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def can_approve_mrm(self, authority_level):
        """Check if user can approve MRM based on their designation"""
        designation_mapping = {
            'Operator': ['Operator'],
            'Supervisor': ['Supervisor'],
            'Squadron Commander': ['Squadron Commander'],
            'Director for Operations': ['Director for Operations'],
            'Commander': ['Commander']
        }

        required_designations = designation_mapping.get(authority_level, [])
        return self.designation in required_designations

    def get_approvable_authority_levels(self):
        """Get list of authority levels this user can approve based on designation"""
        designation_to_authority = {
            'Operator': 'Operator',
            'Supervisor': 'Supervisor',
            'Squadron Commander': 'Squadron Commander',
            'Director for Operations': 'Director for Operations',
            'Commander': 'Commander'
        }

        if self.designation in designation_to_authority:
            return [designation_to_authority[self.designation]]
        return []

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_full_name(self):
        return f"{self.rank} {self.first_name} {self.middle_name} {self.last_name}".strip()

    def get_unit_logo(self):
        logo = UnitLogo.query.filter_by(unit_name=self.unit).first()
        if logo:
            # Updated to handle both local and S3 storage
            from storage import get_storage
            storage = get_storage()
            if hasattr(storage, 's3_client'):  # If using S3
                return logo.logo_filename  # This is the full S3 URL
            else:
                return url_for('get_unit_logo', filename=logo.logo_filename)
        return url_for('static', filename='default_logo.png')

    # Updated relationships - REMOVED UnitAuthority references
    created_hazards = db.relationship(
        'HazardRegistry', backref='hazard_creator', foreign_keys='HazardRegistry.created_by')
    created_mrms = db.relationship(
        'MRMForm', backref='mrm_creator', foreign_keys='MRMForm.created_by')
    reviewed_mrms = db.relationship(
        'MRMForm', backref='mrm_reviewer', foreign_keys='MRMForm.reviewed_by')
    uploaded_unit_logos = db.relationship(
        'UnitLogo', backref='logo_uploader', foreign_keys='UnitLogo.uploaded_by')


# Unit Logos Model
class UnitLogo(db.Model):
    __tablename__ = 'unit_logo'
    id = db.Column(db.Integer, primary_key=True)
    unit_name = db.Column(db.String(100), unique=True,
                          nullable=False, index=True)
    logo_filename = db.Column(db.String(200), nullable=False)
    date_uploaded = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))

# Hazard Registry Model - Updated for PostgreSQL
class HazardRegistry(db.Model):
    __tablename__ = 'hazard_registry'
    id = db.Column(db.Integer, primary_key=True)
    unit = db.Column(db.String(100), nullable=False, index=True)
    
    # CHANGED: Convert Enum to String for PostgreSQL compatibility
    activity_code = db.Column(db.String(20), nullable=False)
    
    hazard_description = db.Column(db.Text, nullable=False)
    before_likelihood = db.Column(db.Integer, nullable=False)
    
    # CHANGED: Convert Enum to String
    before_severity = db.Column(db.String(1), nullable=False)
    
    before_risk_rating = db.Column(db.String(5), nullable=False)
    mitigations = db.Column(db.Text, nullable=False)
    after_likelihood = db.Column(db.Integer, nullable=False)
    
    # CHANGED: Convert Enum to String
    after_severity = db.Column(db.String(1), nullable=False)
    
    after_risk_rating = db.Column(db.String(5), nullable=False)
    date_updated = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.before_likelihood and self.before_severity:
            self.before_risk_rating = self.calculate_risk_rating(
                self.before_likelihood, self.before_severity)
        if self.after_likelihood and self.after_severity:
            self.after_risk_rating = self.calculate_risk_rating(
                self.after_likelihood, self.after_severity)

    def calculate_risk_rating(self, likelihood, severity):
        if likelihood and severity:
            return f"{likelihood}{severity}"
        return "N/A"

    def get_likelihood_description(self, likelihood):
        try:
            likelihood = int(likelihood)
        except (ValueError, TypeError):
            return f"{likelihood} - Unknown"

        descriptions = {
            5: "5 - Frequent",
            4: "4 - Occasional",
            3: "3 - Remote",
            2: "2 - Improbable",
            1: "1 - Extremely Improbable"
        }
        return descriptions.get(likelihood, f"{likelihood} - Unknown")

    def get_severity_description(self, severity):
        if severity is not None:
            severity = str(severity).upper().strip()

        descriptions = {
            'A': "A - Catastrophic",
            'B': "B - Hazardous",
            'C': "C - Major",
            'D': "D - Minor",
            'E': "E - Negligible"
        }
        return descriptions.get(severity, f"{severity} - Unknown")

    def get_risk_color(self, risk_rating):
        red_risks = ['5A', '5B', '5C', '4A', '4B', '3A']
        yellow_risks = ['5D', '5E', '4C', '4D', '4E',
                        '3B', '3C', '3D', '2A', '2B', '2C', '1A']

        if risk_rating in red_risks:
            return 'danger'
        elif risk_rating in yellow_risks:
            return 'warning'
        else:
            return 'success'

# MRM Form Model - Updated for PostgreSQL
class MRMForm(db.Model):
    __tablename__ = 'mrm_form'
    id = db.Column(db.Integer, primary_key=True)
    mrm_number = db.Column(db.String(20), unique=True,
                           nullable=False, index=True)
    activity_mission = db.Column(db.String(255), nullable=False)
    created_by = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    date_created = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    safety_objectives = db.Column(db.Text, nullable=False)
    imsafes = db.Column(db.Text)
    aircraft_vehicle = db.Column(db.String(255))
    environment = db.Column(db.Text)
    mission_statement = db.Column(
        db.Text, default="Minimize risk to ALARP while maintaining operational effectiveness.")
    max_risk = db.Column(db.Integer)
    residual_risk = db.Column(db.Integer)
    total_percent = db.Column(db.Float)

    # CHANGED: Convert Enum to String for PostgreSQL compatibility
    authority_level = db.Column(db.String(30))

    # CHANGED: Convert Enum to String
    status = db.Column(db.String(20), default='draft')
    
    date_submitted = db.Column(db.DateTime)
    date_reviewed = db.Column(db.DateTime)
    
    # CHANGED: Convert Enum to String
    review_status = db.Column(db.String(20), default='pending')
    
    review_notes = db.Column(db.Text)
    creator_signed = db.Column(db.Boolean, default=False)
    creator_signature_date = db.Column(db.DateTime)
    evaluator_signed = db.Column(db.Boolean, default=False)
    evaluator_signature_date = db.Column(db.DateTime)

    # New authority fields
    authority_assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    authority_approved = db.Column(db.Boolean, default=False)
    authority_approval_date = db.Column(db.DateTime)
    authority_signature_date = db.Column(db.DateTime)

    # Updated relationships with unique backref names
    mission_hazards_link = db.relationship(
        'MissionHazards', backref='mrm_form_ref')

    def generate_mrm_number(self):
        """Generate MRM number in format YYYYMMDDNR"""
        from datetime import datetime

        # Get current date in YYYYMMDD format
        date_part = datetime.utcnow().strftime('%Y%m%d')

        # Count how many MRM forms were created today
        today_start = datetime.utcnow().replace(
            hour=0, minute=0, second=0, microsecond=0)
        today_count = MRMForm.query.filter(
            MRMForm.date_created >= today_start
        ).count()

        # Format the number part (NR) with leading zeros
        number_part = f"{today_count + 1:02d}"

        return f"{date_part}{number_part}"


def validate_mrm_creation_data(form_data, current_user):
    """Validate MRM creation data"""
    errors = []

    # Required fields
    if not form_data.get('activity_mission', '').strip():
        errors.append("Activity/Mission is required")

    if not form_data.get('safety_objectives', '').strip():
        errors.append("Safety Objectives are required")

    # I'M SAFE checklist validation
    imsafe_checked = all(
        form_data.get(f'imsafe_{key}') == 'on'
        for key in IMSAFE_CHECKLIST.keys()
    )
    if not imsafe_checked:
        errors.append("All I'M SAFE checklist items must be confirmed")

    # Environment fields validation
    environment_fields = ['environment_weather', 'environment_lighting',
                          'environment_workspace', 'environment_tempo']
    for field in environment_fields:
        if not form_data.get(field):
            errors.append(f"{field.replace('_', ' ').title()} is required")

    # Hazard selection validation
    selected_hazards = form_data.getlist('hazards')
    if not selected_hazards:
        errors.append("At least one hazard must be selected")

    return errors

# Mission Hazards Link Table
class MissionHazards(db.Model):
    __tablename__ = 'mission_hazards'
    id = db.Column(db.Integer, primary_key=True)
    mrm_id = db.Column(db.Integer, db.ForeignKey(
        'mrm_form.id'), nullable=False)
    hazard_id = db.Column(db.Integer, db.ForeignKey(
        'hazard_registry.id'), nullable=False)
    mitigation_override = db.Column(db.Text)
    selected = db.Column(db.Boolean, default=True)
    hazard = db.relationship('HazardRegistry', backref='mission_hazards')

    # Add composite index for better performance
    __table_args__ = (
        db.Index('idx_mrm_hazard', 'mrm_id', 'hazard_id'),
    )


# Constants (These remain the same as they're already strings)
ACTIVITY_CODES = [
    'Airfield', 'Flight', 'Ground', 'Movement', 'Operations',
    'Security', 'Training', 'Base Services', 'Communications',
    'Administration', 'Others'
]

WEATHER_OPTIONS = [
    'Clear skies', 'Overcast / Cloudy', 'Rainy / Wet',
    'Windy', 'Hot / Humid', 'Cold / Foggy'
]

LIGHTING_OPTIONS = [
    'Daylight', 'Dusk / Dawn',
    'Nighttime (Fair)', 'Nighttime (Poor visibility)',
    'Adequate artificial lighting', 'Poor artificial lighting'
]

WORKSPACE_OPTIONS = [
    'Clean and organized', 'Congested / Crowded', 'Slippery / Uneven surface',
    'Hazardous materials present', 'Adequate ventilation', 'Poor ventilation', 'None'
]

OPERATIONAL_TEMPO_OPTIONS = [
    'Normal / Routine operations', 'High tempo / Increased workload',
    'Emergency / Stressful environment'
]

IMSAFE_CHECKLIST = {
    'I': 'Illness - Am I free from any Illness',
    'M': 'Medication - Am I free from any impairing medication?',
    'S': 'Stress - Am I free from stress?',
    'A': 'Alcohol - Am I free from alcohol?',
    'F': 'Fatigue - Am I well rested and alert?',
    'E': 'Eating - Am I adequately nourished?'
}

# Authentication decorators


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        user = get_current_user()
        if user.authority != 'Administrator':
            flash('Administrator access required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


def evaluator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        user = get_current_user()
        if user.authority not in ['Administrator', 'Evaluator']:
            flash('Evaluator access required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def validate_activity_code(value):
    """Validate activity code"""
    if value not in ACTIVITY_CODES:
        raise ValueError(f"Invalid activity code: {value}")
    return value

def validate_severity(value):
    """Validate severity value"""
    valid_severities = ['A', 'B', 'C', 'D', 'E']
    if value.upper() not in valid_severities:
        raise ValueError(f"Invalid severity: {value}")
    return value.upper()

def validate_authority_level(value):
    """Validate authority level"""
    valid_levels = ['Operator', 'Supervisor', 'Squadron Commander', 'Director for Operations', 'Commander']
    if value not in valid_levels:
        raise ValueError(f"Invalid authority level: {value}")
    return value

def validate_status(value):
    """Validate MRM status"""
    valid_statuses = ['draft', 'submitted', 'reviewed']
    if value not in valid_statuses:
        raise ValueError(f"Invalid status: {value}")
    return value

def validate_review_status(value):
    """Validate review status"""
    valid_statuses = ['pending', 'approved', 'rejected', 'needs_revision']
    if value not in valid_statuses:
        raise ValueError(f"Invalid review status: {value}")
    return value

def creator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        user = get_current_user()
        if user.authority not in ['Administrator', 'Evaluator', 'Creator']:
            flash('Creator access required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Helper function to get current user
def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

# Security headers


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Session timeout handling


@app.before_request
def check_session_timeout():
    if 'user_id' in session:
        # Check if session should expire
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=30)
        session.modified = True

# Add input validation decorator


def validate_form_data(required_fields=[]):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            for field in required_fields:
                if not request.form.get(field):
                    flash(f'Missing required field: {field}', 'danger')
                    return redirect(request.referrer or url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Security utility functions


def validate_password_strength(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character"
    return None


def sanitize_input(input_string, max_length=None):
    if input_string is None:
        return ""
    sanitized = str(input_string).strip()
    sanitized = html.escape(sanitized)
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    return sanitized


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg'}


def allowed_image_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# Initialize database with MySQL


def init_db():
    with app.app_context():
        try:
            # Create all tables
            db.create_all()

            # Check if admin user exists
            if not User.query.filter_by(username='admin').first():
                admin = User(
                    username='admin',
                    authority='Administrator',
                    category='Officer',
                    rank='System Administrator',
                    designation='System Admin',  # Add this line
                    first_name='System',
                    last_name='Administrator',
                    serial_number='ADMIN001',
                    branch_of_service='System',
                    unit='IT Department',
                    contact_number='N/A'
                )
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                print("Default admin created: username='admin', password='admin123'")

            print("MySQL Database initialized successfully")

        except Exception as e:
            print(f"Database initialization error: {e}")
            db.session.rollback()


# Initialize database
init_db()

# Context processor


@app.context_processor
def inject_user():
    def get_current_user():
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user:
                user.unit_logo_url = user.get_unit_logo()
            return user
        return None
    return dict(current_user=get_current_user(), csrf_token=generate_csrf)

# ==================== ROUTES ====================


@app.route('/')
@login_required
def index():
    user = get_current_user()

    # Get pending approvals for authority users - FIXED QUERY
    pending_authority_approvals = MRMForm.query.filter(
        MRMForm.authority_assigned_to == user.id,
        MRMForm.authority_approved == False,
        MRMForm.review_status == 'approved',
        MRMForm.status == 'reviewed'
    ).count()

    # Debug: Print authority assignments for current user
    print(
        f"DEBUG: User {user.get_full_name()} has {pending_authority_approvals} pending authority approvals")

    if pending_authority_approvals > 0:
        pending_forms = MRMForm.query.filter(
            MRMForm.authority_assigned_to == user.id,
            MRMForm.authority_approved == False,
            MRMForm.review_status == 'approved',
            MRMForm.status == 'reviewed'
        ).all()
        print(f"DEBUG: Pending forms for {user.get_full_name()}:")
        for form in pending_forms:
            print(
                f"  - MRM {form.mrm_number} (Authority: {form.authority_level})")

    if user.authority == 'Administrator':
        hazard_count = HazardRegistry.query.count()
        mrm_count = MRMForm.query.count()
        user_count = User.query.count()
        pending_reviews = MRMForm.query.filter_by(status='submitted').count()

        # Additional counts for admin
        my_reviews_count = 0
        my_forms_count = MRMForm.query.filter_by(created_by=user.id).count()
        submitted_forms_count = MRMForm.query.filter_by(
            status='submitted').count()

    elif user.authority == 'Evaluator':
        hazard_count = HazardRegistry.query.filter_by(unit=user.unit).count()
        mrm_count = MRMForm.query.filter(
            (MRMForm.reviewed_by == user.id) |
            (MRMForm.status == 'submitted')
        ).count()
        user_count = None
        pending_reviews = MRMForm.query.filter(
            (MRMForm.status == 'submitted') &
            (MRMForm.reviewed_by == user.id)
        ).count()
        my_reviews_count = MRMForm.query.filter_by(reviewed_by=user.id).count()
        my_forms_count = MRMForm.query.filter_by(created_by=user.id).count()
        submitted_forms_count = MRMForm.query.filter_by(
            created_by=user.id, status='submitted').count()

    else:  # Creator
        hazard_count = HazardRegistry.query.filter_by(unit=user.unit).count()
        mrm_count = MRMForm.query.filter_by(created_by=user.id).count()
        user_count = None
        pending_reviews = 0
        my_reviews_count = 0
        my_forms_count = MRMForm.query.filter_by(created_by=user.id).count()
        submitted_forms_count = MRMForm.query.filter_by(
            created_by=user.id, status='submitted').count()

    session_start_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    return render_template('index.html',
                           hazard_count=hazard_count,
                           mrm_count=mrm_count,
                           user_count=user_count,
                           pending_reviews=pending_reviews,
                           my_reviews_count=my_reviews_count,
                           my_forms_count=my_forms_count,
                           submitted_forms_count=submitted_forms_count,
                           pending_authority_approvals=pending_authority_approvals,
                           session_start_time=session_start_time)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username, is_active=True).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['authority'] = user.authority
            flash(f'Welcome back, {user.get_full_name()}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = get_current_user()

    if request.method == 'POST':
        # Get password fields
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Validate password change
        if not old_password:
            flash('Current password is required to make changes.', 'danger')
            return render_template('edit_profile.html', user=user)

        # Verify current password
        if not user.check_password(old_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('edit_profile.html', user=user)

        # Check if new password is provided
        if not new_password:
            flash('New password is required.', 'danger')
            return render_template('edit_profile.html', user=user)

        # Check if passwords match
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return render_template('edit_profile.html', user=user)

        # Validate password strength
        password_error = validate_password_strength(new_password)
        if password_error:
            flash(password_error, 'danger')
            return render_template('edit_profile.html', user=user)

        # Update password
        user.set_password(new_password)

        try:
            db.session.commit()
            flash('Password updated successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating password: ' + str(e), 'danger')

    return render_template('edit_profile.html', user=user)

# Hazard Management Routes


@app.route('/hazards')
@login_required
def view_hazards():
    user = get_current_user()

    # Get search and filter parameters
    search_query = request.args.get('search', '')
    activity_filter = request.args.get('activity_code', '')

    if user.authority == 'Administrator':
        query = HazardRegistry.query
    else:
        query = HazardRegistry.query.filter_by(unit=user.unit)

    # Apply search filter
    if search_query:
        query = query.filter(
            HazardRegistry.hazard_description.ilike(f'%{search_query}%'))

    # Apply activity code filter
    if activity_filter:
        query = query.filter_by(activity_code=activity_filter)

    hazards = query.order_by(HazardRegistry.date_updated.desc()).all()

    return render_template('hazards.html',
                           hazards=hazards,
                           activity_codes=ACTIVITY_CODES,
                           search_query=search_query,
                           activity_filter=activity_filter)


@app.route('/add_hazard', methods=['GET', 'POST'])
@evaluator_required
def add_hazard():
    current_user_obj = get_current_user()

    if request.method == 'POST':
        activity_code = request.form.get('activity_code', '').strip()
        hazard_description = request.form.get('hazard_description', '').strip()
        mitigations = request.form.get('mitigations', '').strip()

        if not all([activity_code, hazard_description, mitigations]):
            flash('All fields are required.', 'danger')
            return render_template('add_hazard.html', activity_codes=ACTIVITY_CODES)

        try:
            before_likelihood = int(request.form.get('before_likelihood', 0))
            after_likelihood = int(request.form.get('after_likelihood', 0))

            if not (1 <= before_likelihood <= 5) or not (1 <= after_likelihood <= 5):
                flash('Likelihood must be between 1 and 5.', 'danger')
                return render_template('add_hazard.html', activity_codes=ACTIVITY_CODES)

        except (ValueError, TypeError):
            flash('Invalid likelihood value.', 'danger')
            return render_template('add_hazard.html', activity_codes=ACTIVITY_CODES)

        try:
            before_severity = validate_severity(request.form.get('before_severity', ''))
            after_severity = validate_severity(request.form.get('after_severity', ''))
        except ValueError as e:
            flash(str(e), 'danger')
            return render_template('add_hazard.html', activity_codes=ACTIVITY_CODES)

        valid_severities = ['A', 'B', 'C', 'D', 'E']
        if before_severity not in valid_severities or after_severity not in valid_severities:
            flash('Invalid severity value.', 'danger')
            return render_template('add_hazard.html', activity_codes=ACTIVITY_CODES)

        new_hazard = HazardRegistry(
            unit=current_user_obj.unit,
            activity_code=activity_code,
            hazard_description=hazard_description,
            before_likelihood=before_likelihood,
            before_severity=before_severity,
            mitigations=mitigations,
            after_likelihood=after_likelihood,
            after_severity=after_severity,
            created_by=current_user_obj.id
        )

        new_hazard.before_risk_rating = new_hazard.calculate_risk_rating(
            before_likelihood, before_severity)
        new_hazard.after_risk_rating = new_hazard.calculate_risk_rating(
            after_likelihood, after_severity)

        try:
            db.session.add(new_hazard)
            db.session.commit()
            flash('Hazard added successfully!', 'success')
            return redirect(url_for('view_hazards'))
        except Exception as e:
            db.session.rollback()
            flash('Error adding hazard: ' + str(e), 'danger')
            return render_template('add_hazard.html', activity_codes=ACTIVITY_CODES)

    return render_template('add_hazard.html', activity_codes=ACTIVITY_CODES)


@app.route('/edit_hazard/<int:hazard_id>', methods=['GET', 'POST'])
@evaluator_required
def edit_hazard(hazard_id):
    try:
        hazard = HazardRegistry.query.get_or_404(hazard_id)

        if request.method == 'POST':
            activity_code = request.form.get('activity_code', '').strip()
            hazard_description = request.form.get(
                'hazard_description', '').strip()
            mitigations = request.form.get('mitigations', '').strip()

            if not all([activity_code, hazard_description, mitigations]):
                flash('All fields are required.', 'danger')
                return render_template('edit_hazard.html', hazard=hazard, activity_codes=ACTIVITY_CODES)

            try:
                before_likelihood = int(
                    request.form.get('before_likelihood', 0))
                after_likelihood = int(request.form.get('after_likelihood', 0))

                if not (1 <= before_likelihood <= 5) or not (1 <= after_likelihood <= 5):
                    flash('Likelihood must be between 1 and 5.', 'danger')
                    return render_template('edit_hazard.html', hazard=hazard, activity_codes=ACTIVITY_CODES)

            except (ValueError, TypeError):
                flash('Invalid likelihood value.', 'danger')
                return render_template('edit_hazard.html', hazard=hazard, activity_codes=ACTIVITY_CODES)

            try:
                before_severity = validate_severity(request.form.get('before_severity', ''))
                after_severity = validate_severity(request.form.get('after_severity', ''))
            except ValueError as e:
                flash(str(e), 'danger')
                return render_template('add_hazard.html', activity_codes=ACTIVITY_CODES)

            valid_severities = ['A', 'B', 'C', 'D', 'E']
            if before_severity not in valid_severities or after_severity not in valid_severities:
                flash('Invalid severity value.', 'danger')
                return render_template('edit_hazard.html', hazard=hazard, activity_codes=ACTIVITY_CODES)

            hazard.activity_code = activity_code
            hazard.hazard_description = hazard_description
            hazard.before_likelihood = before_likelihood
            hazard.before_severity = before_severity
            hazard.mitigations = mitigations
            hazard.after_likelihood = after_likelihood
            hazard.after_severity = after_severity

            hazard.before_risk_rating = hazard.calculate_risk_rating(
                before_likelihood, before_severity)
            hazard.after_risk_rating = hazard.calculate_risk_rating(
                after_likelihood, after_severity)

            db.session.commit()
            flash('Hazard updated successfully!', 'success')
            return redirect(url_for('view_hazards'))

        return render_template('edit_hazard.html', hazard=hazard, activity_codes=ACTIVITY_CODES)

    except Exception as e:
        db.session.rollback()
        flash('Error updating hazard: ' + str(e), 'danger')
        return redirect(url_for('view_hazards'))


@app.route('/delete_hazard/<int:hazard_id>', methods=['POST'])
@evaluator_required
def delete_hazard(hazard_id):
    try:
        hazard = HazardRegistry.query.get_or_404(hazard_id)

        mission_hazards = MissionHazards.query.filter_by(
            hazard_id=hazard_id).first()
        if mission_hazards:
            flash('Cannot delete hazard: It is being used in MRM forms.', 'danger')
            return redirect(url_for('view_hazards'))

        db.session.delete(hazard)
        db.session.commit()
        flash('Hazard deleted successfully!', 'success')

    except Exception as e:
        db.session.rollback()
        flash('Error deleting hazard: ' + str(e), 'danger')

    return redirect(url_for('view_hazards'))

# Enhanced MRM Forms Route with Search and Filter


@app.route('/mrm_forms')
@login_required
def view_mrm_forms():
    user = get_current_user()
    search_query = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    reviewed_by_filter = request.args.get('reviewed_by', '')
    authority_pending = request.args.get('authority_pending', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10

    print(
        f"DEBUG: User {user.get_full_name()} (Authority: {user.authority}, Designation: {user.designation}) accessing MRM forms")

    # Base query based on user role
    if user.authority == 'Administrator':
        query = MRMForm.query
        print("DEBUG: Using ADMIN query - all forms")

    elif user.authority == 'Evaluator':
        # Evaluators see forms they need to review OR forms assigned to them as authority
        query = MRMForm.query.filter(
            (MRMForm.reviewed_by == user.id) |
            (MRMForm.status == 'submitted') |
            (MRMForm.authority_assigned_to == user.id)
        )
        print("DEBUG: Using EVALUATOR query - assigned reviews + submitted forms + authority assignments")

    else:  # Creator and other users
        # Users see forms they created OR forms assigned to them as authority (based on designation)
        query = MRMForm.query.filter(
            (MRMForm.created_by == user.id) |
            (MRMForm.authority_assigned_to == user.id)
        )
        print("DEBUG: Using CREATOR/AUTHORITY query - created by user OR assigned to user")

    # Apply authority pending filter
    if authority_pending:
        query = query.filter(
            MRMForm.authority_assigned_to == user.id,
            MRMForm.authority_approved == False,
            MRMForm.review_status == 'approved',
            MRMForm.status == 'reviewed'
        )
        print("DEBUG: Applied authority pending filter")

    # ... rest of your existing filters and pagination ...

    # Debug: Check authority assignments specifically
    authority_forms = MRMForm.query.filter_by(
        authority_assigned_to=user.id).all()
    print(
        f"DEBUG: User is assigned as authority for {len(authority_forms)} forms:")
    for form in authority_forms:
        assigned_user = User.query.get(form.authority_assigned_to)
        print(f"  - MRM {form.mrm_number} (Authority Level: {form.authority_level}, Assigned To: {assigned_user.get_full_name() if assigned_user else 'None'}, Designation: {assigned_user.designation if assigned_user else 'None'})")
    # Apply pagination
    forms = query.order_by(MRMForm.date_created.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    print(
        f"DEBUG: After pagination - showing {len(forms.items)} forms on page {forms.page}")
    # Pre-load all related users to avoid N+1 queries
    user_ids = set()
    for form in forms.items:
        user_ids.add(form.created_by)
        if form.reviewed_by:
            user_ids.add(form.reviewed_by)
        if form.authority_assigned_to:
            user_ids.add(form.authority_assigned_to)

    # Get all users at once
    users = User.query.filter(User.id.in_(user_ids)).all() if user_ids else []
    user_dict = {user.id: user for user in users}

    # Create lookup dictionaries
    form_creators = {}
    form_authorities = {}

    for form in forms.items:
        creator = user_dict.get(form.created_by)
        if creator:
            form_creators[form.created_by] = creator.get_full_name()

        if form.authority_assigned_to:
            authority_user = user_dict.get(form.authority_assigned_to)
            if authority_user:
                form_authorities[form.authority_assigned_to] = {
                    'name': authority_user.get_full_name(),
                    'designation': authority_user.designation
                }

    return render_template('mrm_forms.html',
                           forms=forms,
                           form_creators=form_creators,
                           form_authorities=form_authorities,
                           search_query=search_query,
                           status_filter=status_filter,
                           reviewed_by_filter=reviewed_by_filter,
                           authority_pending=authority_pending)


@app.route('/debug/authority_assignments')
@login_required
def debug_authority_assignments():
    """Debug route to check authority assignments for current user"""
    user = get_current_user()

    # Get all MRM forms
    all_forms = MRMForm.query.all()

    # Get forms assigned to current user as authority
    user_authority_forms = MRMForm.query.filter_by(
        authority_assigned_to=user.id).all()

    # Get forms that should be assigned to user based on designation
    potential_assignments = MRMForm.query.filter(
        MRMForm.authority_level == user.designation,
        MRMForm.authority_approved == False,
        MRMForm.review_status == 'approved'
    ).all()

    debug_info = {
        'user_info': {
            'name': user.get_full_name(),
            'authority': user.authority,
            'designation': user.designation,
            'unit': user.unit
        },
        'assigned_forms_count': len(user_authority_forms),
        'assigned_forms': [],
        'potential_assignments_count': len(potential_assignments),
        'potential_assignments': [],
        'all_forms_count': len(all_forms),
        'all_forms_authority_levels': {}
    }

    # Count authority levels in all forms
    for form in all_forms:
        level = form.authority_level or 'None'
        debug_info['all_forms_authority_levels'][level] = debug_info['all_forms_authority_levels'].get(
            level, 0) + 1

    # Details for assigned forms
    for form in user_authority_forms:
        debug_info['assigned_forms'].append({
            'mrm_number': form.mrm_number,
            'authority_level': form.authority_level,
            'authority_approved': form.authority_approved,
            'status': form.status,
            'review_status': form.review_status,
            'activity_mission': form.activity_mission
        })

    # Details for potential assignments
    for form in potential_assignments:
        creator = User.query.get(form.created_by)
        debug_info['potential_assignments'].append({
            'mrm_number': form.mrm_number,
            'authority_level': form.authority_level,
            'authority_assigned_to': form.authority_assigned_to,
            'creator_unit': creator.unit if creator else 'Unknown',
            'activity_mission': form.activity_mission,
            'status': form.status,
            'review_status': form.review_status
        })

    return render_template('debug_authority.html', debug_info=debug_info)


@app.route('/fix_all_authority_assignments')
@admin_required
def fix_all_authority_assignments():
    """Fix authority assignments for all MRM forms"""
    try:
        all_forms = MRMForm.query.filter(
            MRMForm.review_status == 'approved',
            MRMForm.authority_approved == False
        ).all()

        fixed_count = 0
        assignment_log = []

        for form in all_forms:
            old_assignee = form.authority_assigned_to
            authority_user = assign_authority_to_mrm(form)

            if authority_user and old_assignee != authority_user.id:
                fixed_count += 1
                assignment_log.append({
                    'mrm_number': form.mrm_number,
                    'authority_level': form.authority_level,
                    'old_assignee': old_assignee,
                    'new_assignee': authority_user.id,
                    'assignee_name': authority_user.get_full_name() if authority_user else 'None'
                })
                print(
                    f"Fixed authority assignment for MRM {form.mrm_number} ({form.authority_level}) -> {authority_user.get_full_name() if authority_user else 'None'}")

        db.session.commit()

        # Return debug info
        return jsonify({
            'success': True,
            'fixed_count': fixed_count,
            'assignments': assignment_log,
            'message': f'Fixed authority assignments for {fixed_count} MRM forms'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# Admin MRM Delete Route


@app.route('/delete_mrm/<int:form_id>', methods=['POST'])
@admin_required
def delete_mrm(form_id):
    try:
        form = MRMForm.query.get_or_404(form_id)
        MissionHazards.query.filter_by(mrm_id=form_id).delete()
        db.session.delete(form)
        db.session.commit()
        flash('MRM form deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting MRM form: {str(e)}', 'danger')
    return redirect(url_for('view_mrm_forms'))

# MRM Creation and Management Routes


@app.route('/create_mrm', methods=['GET', 'POST'])
@creator_required
def create_mrm():
    current_user_obj = get_current_user()
    evaluators = User.query.filter_by(
        authority='Evaluator',
        is_active=True,
        unit=current_user_obj.unit
    ).all()
    hazards = HazardRegistry.query.filter_by(unit=current_user_obj.unit).all()

    if request.method == 'POST':
        try:
            activity_mission = sanitize_input(
                request.form.get('activity_mission'), 255)
            safety_objectives = sanitize_input(
                request.form.get('safety_objectives'))
            reviewed_by = sanitize_input(request.form.get('reviewed_by'))

            if not activity_mission or not safety_objectives:
                flash('Activity/Mission and Safety Objectives are required.', 'danger')
                return render_template('create_mrm.html',
                                       datetime=datetime,
                                       hazards=hazards,
                                       evaluators=evaluators,
                                       activity_codes=ACTIVITY_CODES,
                                       weather_options=WEATHER_OPTIONS,
                                       lighting_options=LIGHTING_OPTIONS,
                                       workspace_options=WORKSPACE_OPTIONS,
                                       tempo_options=OPERATIONAL_TEMPO_OPTIONS,
                                       imsafe_checklist=IMSAFE_CHECKLIST)

            imsafe_values = {}
            for key in IMSAFE_CHECKLIST.keys():
                imsafe_values[key] = request.form.get(
                    f'imsafe_{key}', 'off') == 'on'
            if not all(imsafe_values.values()):
                flash(
                    "All I'M SAFE checklist items must be confirmed before creating an MRM.", "danger")
                return render_template('create_mrm.html',
                                       datetime=datetime,
                                       hazards=hazards,
                                       evaluators=evaluators,
                                       activity_codes=ACTIVITY_CODES,
                                       weather_options=WEATHER_OPTIONS,
                                       lighting_options=LIGHTING_OPTIONS,
                                       workspace_options=WORKSPACE_OPTIONS,
                                       tempo_options=OPERATIONAL_TEMPO_OPTIONS,
                                       imsafe_checklist=IMSAFE_CHECKLIST)

            aircraft_vehicle = sanitize_input(
                request.form.get('aircraft_vehicle', ''))

            environment_data = {
                'weather': request.form.get('environment_weather'),
                'lighting': request.form.get('environment_lighting'),
                'workspace': request.form.get('environment_workspace'),
                'operational_tempo': request.form.get('environment_tempo')
            }
            environment_sentence = generate_environment_sentence(
                environment_data)

            mission_statement = sanitize_input(request.form.get('mission_statement',
                                                                "Minimize risk to ALARP while maintaining operational effectiveness."))

            selected_hazard_ids = request.form.getlist('hazards')
            hazard_mitigations = {}
            for hazard_id in selected_hazard_ids:
                mitigation_key = f'mitigation_{hazard_id}'
                hazard_mitigations[int(hazard_id)] = sanitize_input(
                    request.form.get(mitigation_key, ''))

            # Generate MRM number with retry logic for duplicates
            max_retries = 5
            mrm_number = None

            for attempt in range(max_retries):
                try:
                    mrm_number = generate_mrm_number()

                    # Check if this number already exists (double-check)
                    existing_mrm = MRMForm.query.filter_by(
                        mrm_number=mrm_number).first()
                    if existing_mrm:
                        # If it exists, wait a bit and try again
                        import time
                        time.sleep(0.1)
                        continue

                    # Create the MRM form
                    new_mrm = MRMForm(
                        mrm_number=mrm_number,
                        activity_mission=activity_mission,
                        created_by=current_user_obj.id,
                        reviewed_by=reviewed_by if reviewed_by else None,
                        safety_objectives=safety_objectives,
                        imsafes=json.dumps(imsafe_values),
                        aircraft_vehicle=aircraft_vehicle,
                        environment=environment_sentence,
                        mission_statement=mission_statement,
                        review_status='pending'
                    )

                    db.session.add(new_mrm)
                    db.session.flush()  # This gets the ID without committing

                    for hazard_id, mitigation_override in hazard_mitigations.items():
                        mission_hazard = MissionHazards(
                            mrm_id=new_mrm.id,
                            hazard_id=hazard_id,
                            mitigation_override=mitigation_override if mitigation_override else None,
                            selected=True
                        )
                        db.session.add(mission_hazard)

                    calculate_mission_risks(new_mrm)
                    db.session.commit()
                    flash('MRM Form created successfully!', 'success')
                    return redirect(url_for('view_mrm_forms'))

                except Exception as e:
                    db.session.rollback()
                    if "Duplicate entry" in str(e) and attempt < max_retries - 1:
                        # Duplicate error, try again with new number
                        continue
                    else:
                        # Other error or max retries reached
                        raise e

            # If we get here, all retries failed
            flash(
                'Failed to generate unique MRM number after multiple attempts. Please try again.', 'danger')
            return render_template('create_mrm.html',
                                   datetime=datetime,
                                   hazards=hazards,
                                   evaluators=evaluators,
                                   activity_codes=ACTIVITY_CODES,
                                   weather_options=WEATHER_OPTIONS,
                                   lighting_options=LIGHTING_OPTIONS,
                                   workspace_options=WORKSPACE_OPTIONS,
                                   tempo_options=OPERATIONAL_TEMPO_OPTIONS,
                                   imsafe_checklist=IMSAFE_CHECKLIST)

        except Exception as e:
            db.session.rollback()
            flash('Error creating MRM form: ' + str(e), 'danger')
            return render_template('create_mrm.html',
                                   datetime=datetime,
                                   hazards=hazards,
                                   evaluators=evaluators,
                                   activity_codes=ACTIVITY_CODES,
                                   weather_options=WEATHER_OPTIONS,
                                   lighting_options=LIGHTING_OPTIONS,
                                   workspace_options=WORKSPACE_OPTIONS,
                                   tempo_options=OPERATIONAL_TEMPO_OPTIONS,
                                   imsafe_checklist=IMSAFE_CHECKLIST)

    return render_template('create_mrm.html',
                           datetime=datetime,
                           hazards=hazards,
                           evaluators=evaluators,
                           activity_codes=ACTIVITY_CODES,
                           weather_options=WEATHER_OPTIONS,
                           lighting_options=LIGHTING_OPTIONS,
                           workspace_options=WORKSPACE_OPTIONS,
                           tempo_options=OPERATIONAL_TEMPO_OPTIONS,
                           imsafe_checklist=IMSAFE_CHECKLIST)


def generate_mrm_number():
    """Generate MRM number in format YYYYMMDDNR with proper collision handling"""
    from datetime import datetime

    # Get current date in YYYYMMDD format
    date_part = datetime.utcnow().strftime('%Y%m%d')

    # Count how many MRM forms were created today
    today_start = datetime.utcnow().replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    # Get the highest number used today
    latest_mrm_today = MRMForm.query.filter(
        MRMForm.mrm_number.like(f"{date_part}%")
    ).order_by(MRMForm.mrm_number.desc()).first()

    if latest_mrm_today:
        # Extract the number part and increment
        existing_number = latest_mrm_today.mrm_number
        number_part = int(existing_number[8:])  # Get last 2 digits
        new_number = number_part + 1
    else:
        # First MRM of the day
        new_number = 1

    # Ensure the number doesn't exceed 2 digits (01-99)
    if new_number > 99:
        # If we exceed 99 forms in one day, add a letter suffix
        # This is extremely unlikely but handles the edge case
        letter_suffix = chr(64 + (new_number - 99))  # A, B, C, etc.
        number_part = f"99{letter_suffix}"
    else:
        # Format the number part with leading zeros
        number_part = f"{new_number:02d}"

    return f"{date_part}{number_part}"


def generate_environment_sentence(environment_data):
    parts = []
    if environment_data.get('weather'):
        parts.append(environment_data['weather'].capitalize())
    if environment_data.get('lighting'):
        parts.append(environment_data['lighting'].capitalize())
    if environment_data.get('workspace'):
        parts.append(environment_data['workspace'].capitalize())
    if environment_data.get('operational_tempo'):
        parts.append(environment_data['operational_tempo'].capitalize())
    if parts:
        return ". ".join(parts) + "."
    else:
        return "Standard operational environment."


def calculate_mission_risks(mrm_form):
    mission_hazards = MissionHazards.query.filter_by(
        mrm_id=mrm_form.id, selected=True).all()
    max_risk = len(mission_hazards) * 3
    if max_risk == 0:
        max_risk = 1

    residual_risk = 0
    for mission_hazard in mission_hazards:
        risk_color = mission_hazard.hazard.get_risk_color(
            mission_hazard.hazard.after_risk_rating)
        if risk_color == 'success':
            residual_risk += 1
        elif risk_color == 'warning':
            residual_risk += 2
        elif risk_color == 'danger':
            residual_risk += 3

    total_percent = (residual_risk / max_risk) * 100

    if total_percent <= 50:
        authority_level = "Operator"
    elif total_percent <= 65:
        authority_level = "Supervisor"
    elif total_percent <= 84:
        authority_level = "Squadron Commander"
    else:
        authority_level = "Director for Operations"

    mrm_form.max_risk = max_risk
    mrm_form.residual_risk = residual_risk
    mrm_form.total_percent = total_percent
    mrm_form.authority_level = authority_level


@app.route('/edit_mrm/<int:form_id>', methods=['GET', 'POST'])
@creator_required
def edit_mrm(form_id):
    """Edit an unsubmitted MRM form"""
    form = MRMForm.query.get_or_404(form_id)
    user = get_current_user()

    # Security check - only creator can edit their own draft forms
    if form.created_by != user.id or form.status != 'draft':
        flash('You can only edit your own draft forms.', 'danger')
        return redirect(url_for('view_mrm_forms'))

    current_user_obj = get_current_user()
    evaluators = User.query.filter_by(
        authority='Evaluator',
        is_active=True,
        unit=current_user_obj.unit
    ).all()
    hazards = HazardRegistry.query.filter_by(unit=current_user_obj.unit).all()

    # Get currently selected hazards
    current_hazards = MissionHazards.query.filter_by(
        mrm_id=form.id, selected=True).all()
    current_hazard_ids = [mh.hazard_id for mh in current_hazards]
    hazard_mitigations = {
        mh.hazard_id: mh.mitigation_override for mh in current_hazards}

    # PARSE EXISTING ENVIRONMENT DATA
    environment_data = {
        'weather': '',
        'lighting': '',
        'workspace': '',
        'operational_tempo': ''
    }

    if form.environment:
        # Parse the environment sentence back into individual components
        env_parts = [part.strip()
                     for part in form.environment.split('.') if part.strip()]

        for part in env_parts:
            part_lower = part.lower()
            # Match weather options
            if any(weather in part_lower for weather in ['clear', 'sunny', 'overcast', 'cloudy', 'rain', 'wet', 'wind', 'hot', 'humid', 'cold', 'foggy']):
                # Find the exact match from weather_options
                for option in WEATHER_OPTIONS:
                    if any(word in part_lower for word in option.lower().split()):
                        environment_data['weather'] = option
                        break

            # Match lighting options
            elif any(lighting in part_lower for lighting in ['daylight', 'bright', 'dusk', 'dawn', 'nighttime', 'fair', 'poor visibility', 'artificial lighting']):
                for option in LIGHTING_OPTIONS:
                    if any(word in part_lower for word in option.lower().split()):
                        environment_data['lighting'] = option
                        break

            # Match workspace options - FIXED THE TYPO HERE
            elif any(workspace in part_lower for workspace in ['clean', 'organized', 'congested', 'crowded', 'slippery', 'uneven', 'hazardous materials', 'adequate ventilation', 'poor ventilation']):
                for option in WORKSPACE_OPTIONS:
                    if any(word in part_lower for word in option.lower().split()):
                        environment_data['workspace'] = option
                        break

            # Match operational tempo options
            elif any(tempo in part_lower for tempo in ['normal', 'routine', 'high tempo', 'increased workload', 'emergency', 'stressful']):
                for option in OPERATIONAL_TEMPO_OPTIONS:
                    if any(word in part_lower for word in option.lower().split()):
                        environment_data['operational_tempo'] = option
                        break

    if request.method == 'POST':
        try:
            # Update form data
            form.activity_mission = sanitize_input(
                request.form.get('activity_mission'), 255)
            form.safety_objectives = sanitize_input(
                request.form.get('safety_objectives'))

            # Handle reviewed_by - convert to integer if provided
            reviewed_by_input = request.form.get('reviewed_by')
            form.reviewed_by = int(
                reviewed_by_input) if reviewed_by_input and reviewed_by_input.isdigit() else None

            form.aircraft_vehicle = sanitize_input(
                request.form.get('aircraft_vehicle', ''))

            # Update environment from form data
            environment_data = {
                'weather': request.form.get('environment_weather'),
                'lighting': request.form.get('environment_lighting'),
                'workspace': request.form.get('environment_workspace'),
                'operational_tempo': request.form.get('environment_tempo')
            }
            form.environment = generate_environment_sentence(environment_data)

            form.mission_statement = sanitize_input(request.form.get('mission_statement',
                                                                     "Minimize risk to ALARP while maintaining operational effectiveness."))

            # Update I'M SAFE checklist
            imsafe_values = {}
            for key in IMSAFE_CHECKLIST.keys():
                imsafe_values[key] = request.form.get(
                    f'imsafe_{key}', 'off') == 'on'
            form.imsafes = json.dumps(imsafe_values)

            # Clear existing hazard selections
            MissionHazards.query.filter_by(mrm_id=form.id).delete()

            # Add new hazard selections
            selected_hazard_ids = request.form.getlist('hazards')
            for hazard_id in selected_hazard_ids:
                mitigation_key = f'mitigation_{hazard_id}'
                mitigation_override = sanitize_input(
                    request.form.get(mitigation_key, ''))

                mission_hazard = MissionHazards(
                    mrm_id=form.id,
                    hazard_id=int(hazard_id),
                    mitigation_override=mitigation_override if mitigation_override else None,
                    selected=True
                )
                db.session.add(mission_hazard)

            # Recalculate risks
            calculate_mission_risks(form)

            db.session.commit()
            flash('MRM Form updated successfully!', 'success')
            return redirect(url_for('view_mrm_forms'))

        except Exception as e:
            db.session.rollback()
            flash('Error updating MRM form: ' + str(e), 'danger')

    # Load I'M SAFE values for form
    imsafe_values = json.loads(form.imsafes) if form.imsafes else {}

    return render_template('edit_mrm.html',
                           form=form,
                           hazards=hazards,
                           evaluators=evaluators,
                           current_hazard_ids=current_hazard_ids,
                           hazard_mitigations=hazard_mitigations,
                           imsafe_values=imsafe_values,
                           environment_data=environment_data,
                           activity_codes=ACTIVITY_CODES,
                           weather_options=WEATHER_OPTIONS,
                           lighting_options=LIGHTING_OPTIONS,
                           workspace_options=WORKSPACE_OPTIONS,
                           tempo_options=OPERATIONAL_TEMPO_OPTIONS,
                           imsafe_checklist=IMSAFE_CHECKLIST)


@app.route('/delete_mrm_creator/<int:form_id>', methods=['POST'])
@creator_required
def delete_mrm_creator(form_id):
    """Delete an unsubmitted MRM form (creator only)"""
    try:
        form = MRMForm.query.get_or_404(form_id)
        user = get_current_user()

        # Security check - only creator can delete their own draft forms
        if form.created_by != user.id or form.status != 'draft':
            flash('You can only delete your own draft forms.', 'danger')
            return redirect(url_for('view_mrm_forms'))

        # Delete associated hazards
        MissionHazards.query.filter_by(mrm_id=form_id).delete()

        # Delete the form
        db.session.delete(form)
        db.session.commit()

        flash('MRM form deleted successfully!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting MRM form: {str(e)}', 'danger')

    return redirect(url_for('view_mrm_forms'))


@app.route('/view_mrm/<int:form_id>')
@login_required
def view_mrm(form_id):
    form = MRMForm.query.get_or_404(form_id)
    user = get_current_user()

    # Security check - only creator can view their own forms, or evaluators/admins
    if user.authority == 'Creator' and form.created_by != user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('view_mrm_forms'))

    # Get related users
    creator = User.query.get(form.created_by) if form.created_by else None
    reviewer = User.query.get(form.reviewed_by) if form.reviewed_by else None
    evaluator = User.query.get(form.reviewed_by) if form.reviewed_by else None
    authority_user = User.query.get(
        form.authority_assigned_to) if form.authority_assigned_to else None

    # Get mission hazards
    mission_hazards = MissionHazards.query.filter_by(
        mrm_id=form.id, selected=True).all()

    # Parse I'M SAFE values
    imsafe_values = json.loads(form.imsafes) if form.imsafes else {}

    return render_template('view_mrm.html',
                           form=form,
                           mission_hazards=mission_hazards,
                           creator=creator,
                           reviewer=reviewer,
                           evaluator=evaluator,
                           authority_user=authority_user,
                           imsafe_values=imsafe_values,
                           imsafe_checklist=IMSAFE_CHECKLIST)


@app.route('/submit_mrm/<int:form_id>')
@creator_required
def submit_mrm(form_id):
    form = MRMForm.query.get_or_404(form_id)
    user = get_current_user()

    if form.created_by != user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('view_mrm_forms'))

    form.status = 'submitted'
    form.date_submitted = datetime.utcnow()

    if user.signature_filename:
        form.creator_signed = True
        form.creator_signature_date = datetime.utcnow()
        flash('MRM submitted and signed!', 'success')
    else:
        flash('MRM submitted! (Note: Please upload your signature)', 'warning')

    db.session.commit()
    return redirect(url_for('view_mrm_forms'))

# User Management Routes


@app.route('/manage_users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('users.html', users=users)


@app.route('/add_user', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        authority = request.form['authority']
        category = request.form['category']
        rank = request.form.get('rank', '').strip()
        designation = request.form.get(
            'designation', '').strip()  # Add this line
        first_name = request.form['first_name'].strip()
        middle_name = request.form.get('middle_name', '').strip()
        last_name = request.form['last_name'].strip()
        serial_number = request.form['serial_number'].strip()
        branch_of_service = request.form['branch_of_service'].strip()
        unit = request.form['unit'].strip()
        contact_number = request.form.get('contact_number', '').strip()

        password_error = validate_password_strength(password)
        if password_error:
            flash(password_error, 'danger')
            return render_template('add_user.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('add_user.html')

        new_user = User(
            username=username,
            authority=authority,
            category=category,
            rank=rank,
            designation=designation,  # Add this line
            first_name=first_name,
            middle_name=middle_name,
            last_name=last_name,
            serial_number=serial_number,
            branch_of_service=branch_of_service,
            unit=unit,
            contact_number=contact_number
        )
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully!', 'success')
            return redirect(url_for('manage_users'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating user: ' + str(e), 'danger')
            return render_template('add_user.html')

    return render_template('add_user.html')

# Unit Logo Management Routes


@app.route('/manage_logos')
@admin_required
def manage_logos():
    logos = UnitLogo.query.all()
    units = db.session.query(User.unit).distinct().all()
    unit_list = [unit[0] for unit in units]
    return render_template('manage_logos.html', logos=logos, units=unit_list)


@app.route('/upload_logo', methods=['POST'])
@admin_required
def upload_logo():
    if 'logo' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('manage_logos'))

    file = request.files['logo']
    unit_name = request.form.get('unit_name')

    if file.filename == '' or not unit_name:
        flash('No file selected or unit name missing', 'danger')
        return redirect(url_for('manage_logos'))

    if file and allowed_image_file(file.filename):
        old_logo = UnitLogo.query.filter_by(unit_name=unit_name).first()
        if old_logo:
            old_path = os.path.join(
                app.config['LOGO_FOLDER'], old_logo.logo_filename)
            if os.path.exists(old_path):
                os.remove(old_path)
            db.session.delete(old_logo)

        filename = f"logo_{unit_name}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}{os.path.splitext(file.filename)[1]}"
        filepath = os.path.join(app.config['LOGO_FOLDER'], filename)
        file.save(filepath)

        new_logo = UnitLogo(
            unit_name=unit_name,
            logo_filename=filename,
            uploaded_by=get_current_user().id
        )
        db.session.add(new_logo)
        db.session.commit()
        flash('Logo uploaded successfully!', 'success')
    else:
        flash('Invalid file type. Please upload PNG, JPG, or JPEG.', 'danger')
    return redirect(url_for('manage_logos'))


@app.route('/delete_logo/<int:logo_id>', methods=['POST'])
@admin_required
def delete_logo(logo_id):
    """Delete a unit logo"""
    try:
        logo = UnitLogo.query.get_or_404(logo_id)

        # Delete the physical file
        file_path = os.path.join(app.config['LOGO_FOLDER'], logo.logo_filename)
        if os.path.exists(file_path):
            os.remove(file_path)

        # Delete the database record
        db.session.delete(logo)
        db.session.commit()

        flash(f'Logo for {logo.unit_name} deleted successfully!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting logo: {str(e)}', 'danger')

    return redirect(url_for('manage_logos'))


@app.route('/unit_logo/<filename>')
def get_unit_logo(filename):
    return send_from_directory(app.config['LOGO_FOLDER'], filename)


# Include other essential routes...


@app.route('/sign_mrm/<int:form_id>', methods=['GET', 'POST'])
@login_required
def sign_mrm(form_id):
    form = MRMForm.query.get_or_404(form_id)
    user = get_current_user()

    if form.created_by != user.id:
        flash('Only the creator can sign this MRM form.', 'danger')
        return redirect(url_for('view_mrm_forms'))

    if not user.signature_filename:
        flash('Please upload your signature first.', 'warning')
        return redirect(url_for('upload_signature'))

    if request.method == 'POST':
        form.creator_signed = True
        form.creator_signature_date = datetime.utcnow()
        db.session.commit()
        flash('MRM signed successfully!', 'success')
        return redirect(url_for('view_mrm_forms'))

    return render_template('sign_mrm.html', form=form)


@app.route('/evaluator_sign_mrm/<int:form_id>', methods=['GET', 'POST'])
@evaluator_required
def evaluator_sign_mrm(form_id):
    form = MRMForm.query.get_or_404(form_id)
    user = get_current_user()

    if form.reviewed_by != user.id or form.review_status != 'approved':
        flash('You can only sign approved MRM forms assigned to you.', 'danger')
        return redirect(url_for('view_mrm_forms'))

    if not user.signature_filename:
        flash('Please upload your signature first.', 'warning')
        return redirect(url_for('upload_signature'))

    if request.method == 'POST':
        form.evaluator_signed = True
        form.evaluator_signature_date = datetime.utcnow()
        db.session.commit()
        flash('MRM signed successfully!', 'success')
        return redirect(url_for('view_mrm_forms'))

    return render_template('evaluator_sign_mrm.html', form=form)


# Update the review_mrm route to auto-assign authority

@app.route('/review_mrm/<int:form_id>', methods=['GET', 'POST'])
@evaluator_required
def review_mrm(form_id):
    form = MRMForm.query.get_or_404(form_id)
    user = get_current_user()

    # Check if user is assigned as reviewer OR is admin
    if form.reviewed_by != user.id and user.authority != 'Administrator':
        flash('You are not assigned to review this MRM form.', 'danger')
        return redirect(url_for('view_mrm_forms'))

    # Get the creator and find potential authority users based on DESIGNATION
    creator = User.query.get(form.created_by) if form.created_by else None
    potential_authorities = []

    if creator and creator.unit:
        # Find users with designations that match the required authority level
        authority_to_designation = {
            'Operator': 'Operator',
            'Supervisor': 'Supervisor',
            'Squadron Commander': 'Squadron Commander',
            'Director for Operations': 'Director for Operations',
            'Commander': 'Commander'
        }

        required_designation = authority_to_designation.get(
            form.authority_level)
        if required_designation:
            potential_authorities = User.query.filter(
                User.unit == creator.unit,
                User.designation == required_designation,
                User.is_active == True
            ).all()

    if request.method == 'POST':
        review_status = request.form.get('review_status', 'approved')
        review_notes = request.form.get('review_notes', '').strip()
        auto_sign = request.form.get('auto_sign', 'false') == 'true'

        form.review_status = review_status
        form.review_notes = review_notes
        form.date_reviewed = datetime.utcnow()
        form.status = 'reviewed'

        if review_status == 'approved':
            # Auto-assign to appropriate authority based on DESIGNATION
            authority_user = assign_authority_to_mrm(form)
            if authority_user:
                form.authority_assigned_to = authority_user.id
                form.authority_approved = False
                form.authority_approval_date = None
                form.authority_signature_date = None

                flash(
                    f'MRM approved and assigned to {authority_user.get_full_name()} ({authority_user.designation}) for final authorization!',
                    'success'
                )
            else:
                flash(
                    f'MRM approved! No user with {form.authority_level} designation found in {creator.unit if creator else "the unit"}.', 'warning')

            if auto_sign and user.signature_filename:
                form.evaluator_signed = True
                form.evaluator_signature_date = datetime.utcnow()

        db.session.commit()
        return redirect(url_for('view_mrm_forms'))

    return render_template('review_mrm.html',
                           form=form,
                           creator=creator,
                           potential_authorities=potential_authorities,  # Changed from unit_users
                           current_user=user)


def assign_authority_to_mrm(mrm_form):
    """Assign MRM to the appropriate authority based on authority_level and user designation"""
    creator = User.query.get(mrm_form.created_by)

    if not creator:
        return None

    print(
        f"DEBUG: Assigning authority for MRM {mrm_form.id}, required authority_level: {mrm_form.authority_level}")

    # Map authority levels to designations
    authority_to_designation = {
        'Operator': 'Operator',
        'Supervisor': 'Supervisor',
        'Squadron Commander': 'Squadron Commander',
        'Director for Operations': 'Director for Operations',
        'Commander': 'Commander'
    }

    required_designation = authority_to_designation.get(
        mrm_form.authority_level)

    if not required_designation:
        print(
            f"DEBUG: No designation mapping found for authority_level: {mrm_form.authority_level}")
        return None

    print(
        f"DEBUG: Looking for user with designation: {required_designation} in unit: {creator.unit}")

    # Special cases for Operator and Supervisor
    if mrm_form.authority_level == 'Operator':
        # Operator is the creator themselves - auto-approve
        mrm_form.authority_approved = True
        mrm_form.authority_approval_date = datetime.utcnow()
        print(
            f"DEBUG: Assigned to Operator (Creator) - {creator.get_full_name()}")
        return creator

    elif mrm_form.authority_level == 'Supervisor':
        # Supervisor is the evaluator who reviewed the MRM
        evaluator = User.query.get(mrm_form.reviewed_by)
        if evaluator:
            mrm_form.authority_approved = True
            mrm_form.authority_approval_date = datetime.utcnow()
            print(
                f"DEBUG: Assigned to Supervisor (Evaluator) - {evaluator.get_full_name()}")
        else:
            print(f"DEBUG: No evaluator found for Supervisor assignment")
        return evaluator

    else:
        # Higher authorities: Find users with matching DESIGNATION (not authority) in the same unit
        authority_user = User.query.filter(
            User.unit == creator.unit,
            User.designation == required_designation,  # Use designation, not authority
            User.is_active == True
        ).first()

        if authority_user:
            print(
                f"DEBUG: Found authority user - {authority_user.get_full_name()} with designation {authority_user.designation}")
            # Don't auto-approve for higher authorities - they need to manually approve
            mrm_form.authority_approved = False
            mrm_form.authority_approval_date = None
            mrm_form.authority_signature_date = None
        else:
            print(
                f"DEBUG: No user found with designation {required_designation} in unit {creator.unit}")
            # List available users with designations in the unit for debugging
            unit_users_with_designations = User.query.filter(
                User.unit == creator.unit,
                User.is_active == True,
                User.designation.isnot(None)
            ).all()
            print(
                f"DEBUG: Available users with designations in unit {creator.unit}:")
            for user in unit_users_with_designations:
                print(
                    f"  - {user.get_full_name()} (Designation: {user.designation}, Authority: {user.authority})")

        return authority_user
# Add authority approval route


@app.route('/authority_approve_mrm/<int:form_id>', methods=['POST'])
@login_required
def authority_approve_mrm(form_id):
    form = MRMForm.query.get_or_404(form_id)
    user = get_current_user()

    # Check if user is assigned as authority for this MRM
    if form.authority_assigned_to != user.id:
        flash('You are not authorized to approve this MRM.', 'danger')
        return redirect(url_for('view_mrm_forms'))

    # Check if user has signature
    if not user.signature_filename:
        flash('Please upload your signature before approving MRM forms.', 'warning')
        return redirect(url_for('upload_signature'))

    # Approve the MRM
    form.authority_approved = True
    form.authority_approval_date = datetime.utcnow()
    form.authority_signature_date = datetime.utcnow()

    db.session.commit()

    flash('MRM authorized successfully!', 'success')
    return redirect(url_for('view_mrm', form_id=form_id))


# Add these routes after the existing routes in app.py

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        username = request.form['username'].strip()
        authority = request.form['authority']
        category = request.form['category']
        rank = request.form.get('rank', '').strip()
        designation = request.form.get(
            'designation', '').strip()  # Add this line
        first_name = request.form['first_name'].strip()
        middle_name = request.form.get('middle_name', '').strip()
        last_name = request.form['last_name'].strip()
        serial_number = request.form['serial_number'].strip()
        branch_of_service = request.form['branch_of_service'].strip()
        unit = request.form['unit'].strip()
        contact_number = request.form.get('contact_number', '').strip()
        is_active = request.form.get('is_active') == 'on'

        # Check if username already exists (excluding current user)
        existing_user = User.query.filter(
            User.username == username, User.id != user.id).first()
        if existing_user:
            flash('Username already exists.', 'danger')
            return render_template('edit_user.html', user=user)

        # Update user
        user.username = username
        user.authority = authority
        user.category = category
        user.rank = rank
        user.designation = designation  # Add this line
        user.first_name = first_name
        user.middle_name = middle_name
        user.last_name = last_name
        user.serial_number = serial_number
        user.branch_of_service = branch_of_service
        user.unit = unit
        user.contact_number = contact_number
        user.is_active = is_active

        # Update password if provided
        password = request.form.get('password')
        if password:
            password_error = validate_password_strength(password)
            if password_error:
                flash(password_error, 'danger')
                return render_template('edit_user.html', user=user)
            user.set_password(password)

        try:
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('manage_users'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating user: ' + str(e), 'danger')

    return render_template('edit_user.html', user=user)


@app.route('/toggle_user/<int:user_id>', methods=['POST'])
@admin_required
def toggle_user(user_id):
    if user_id == session['user_id']:
        flash('You cannot deactivate your own account.', 'danger')
        return redirect(url_for('manage_users'))

    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active

    try:
        db.session.commit()
        flash(
            f'User {"activated" if user.is_active else "deactivated"} successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating user status: ' + str(e), 'danger')

    return redirect(url_for('manage_users'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('manage_users'))

    user = User.query.get_or_404(user_id)

    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting user: ' + str(e), 'danger')

    return redirect(url_for('manage_users'))


@app.route('/mrm/<int:form_id>/pdf')
@login_required
def mrm_pdf(form_id):
    from io import BytesIO
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Image, Spacer
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    import os

    form = MRMForm.query.get_or_404(form_id)
    creator = User.query.get(form.created_by)
    reviewer = User.query.get(form.reviewed_by) if form.reviewed_by else None
    authority_user = User.query.get(
        form.authority_assigned_to) if form.authority_assigned_to else None
    hazards = MissionHazards.query.filter_by(
        mrm_id=form.id, selected=True).all()

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=20, rightMargin=20, topMargin=18, bottomMargin=18
    )
    elements = []
    styles = getSampleStyleSheet()
    small = ParagraphStyle(
        "small", parent=styles["Normal"], fontSize=9, leading=11)
    header_title_style = ParagraphStyle(
        "headertitle", parent=styles["Title"], alignment=1, fontSize=14, leading=16)

    hazard_colWidths = [25, 140, 60, 60, 60, 200, 60, 60, 60]  # total = 725

    # === HEADER PART 1: Logo + Title ===
    logo_path = os.path.join(app.static_folder, "logo.png")
    logo_img = Image(logo_path, width=50, height=50) if os.path.exists(
        logo_path) else Paragraph("LOGO", small)

    header1_data = [[
        logo_img,
        Paragraph(
            "<b>MISSION RISK MANAGEMENT (MRM) FORM</b>"
            "<br/><font size=9>Air Force Safety Office: 2024 version</font>",
            header_title_style
        )
    ]]
    header1_table = Table(header1_data, colWidths=[60, 665])  # total 725
    header1_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.4, colors.black),
        ('ALIGN', (1, 0), (1, 0), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(header1_table)

    # --- Signature helper ---
    def get_signature_image(user, signed, signature_date, width=80, height=25):
        """Get signature image or placeholder"""
        if user and signed and user.signature_filename:
            sig_path = os.path.join(app.config.get(
                'SIGNATURE_FOLDER', ''), user.signature_filename)
            if os.path.exists(sig_path):
                return Image(sig_path, width=width, height=height)

        # Return placeholder text if no signature
        return Paragraph("__________________", small)

    # === HEADER PART 2: Mission/Activity, Compiled by, Reviewed by, Date ===
    # Get signatures for creator and reviewer with smaller dimensions
    creator_sig = get_signature_image(
        creator, form.creator_signed, form.creator_signature_date, width=80, height=25)
    reviewer_sig = get_signature_image(
        reviewer, form.evaluator_signed, form.evaluator_signature_date, width=80, height=25)

    # Adjusted column widths - larger Mission/Activity, smaller signature columns
    header2_data = [[
        Paragraph(
            f"<b>Mission/Activity:</b><br/><br/>{form.activity_mission or ''}", small),
        Paragraph(
            f"<b>Compiled by:</b><br/>{creator.get_full_name() if creator else 'N/A'}<br/>", small),
        creator_sig,  # Creator signature with smaller size
        Paragraph(
            f"<b>Reviewed by:</b><br/>{reviewer.get_full_name() if reviewer else 'N/A'}<br/>", small),
        reviewer_sig,  # Reviewer signature with smaller size
        Paragraph(
            f"<b>Date:</b><br/><br/>{form.date_created.strftime('%d %B %Y') if form.date_created else ''}", small)
    ]]
    # New column widths: Larger Mission/Activity, smaller signatures
    header2_table = Table(header2_data, colWidths=[
                          # total 725 (300 + 90 + 80 + 90 + 80 + 85)
                          300, 90, 80, 90, 80, 85])
    header2_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.4, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    elements.append(header2_table)

    # === HEADER PART 3: Objective ===
    row_obj = [[Paragraph(
        f"<b>Mission/Activity Objective:</b> {form.safety_objectives or ''}<br/><br/>",
        small)]]
    row_obj_table = Table(row_obj, colWidths=[725])
    row_obj_table.setStyle(TableStyle(
        [('GRID', (0, 0), (-1, -1), 0.4, colors.black)]))
    elements.append(row_obj_table)

    # === HEADER PART 4: Assumptions ===
    assump_style = ParagraphStyle(
        "assump_center", parent=styles["Normal"], fontSize=10, alignment=1)
    row_assump = [
        [Paragraph("<b>Assumptions / Nominal Conditions</b>", assump_style)]]
    row_assump_table = Table(row_assump, colWidths=[725])
    row_assump_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.4, colors.black),
        ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
    ]))
    elements.append(row_assump_table)

    # === HEADER PART 5: Crew + Environment ===
    row4_data = [[
        Paragraph(f"<b>Crew/Personnel:</b> I.M.S.A.F.E.", small),
        Paragraph(f"<b>Environment:</b> {form.environment or ''}", small)
    ]]
    row4_table = Table(row4_data, colWidths=[362.5, 362.5])  # total 725
    row4_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.4, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    elements.append(row4_table)

    # === HEADER PART 6: Vehicle + Mission ===
    row5_data = [[
        Paragraph(
            f"<b>Aircraft/Vehicle:</b> {form.aircraft_vehicle or ''}", small),
        Paragraph(f"<b>Mission:</b> {form.mission_statement or ''}", small)
    ]]
    row5_table = Table(row5_data, colWidths=[362.5, 362.5])
    row5_table.setStyle(TableStyle(
        [('GRID', (0, 0), (-1, -1), 0.4, colors.black)]))
    elements.append(row5_table)

    # === RISK COLOR FUNCTION ===
    def risk_color(likelihood=None, severity=None, rating=None):
        try:
            if rating:
                r = str(rating).strip().upper()
                if len(r) == 2 and r[0].isdigit() and r[1].isalpha():
                    likelihood, severity = r[0], r[1]
            lik = int(likelihood or 0)
            sev_map = {"A": 5, "B": 4, "C": 3, "D": 2, "E": 1}
            sev = sev_map.get(str(severity).upper(), 0)
            score = sev * lik
            if score >= 15:
                return colors.red
            elif score >= 6:
                return colors.yellow
            return colors.green
        except:
            return colors.white

    # === HAZARD TABLE ===
    data = [
        ["NR", "Risk Identified (RI)", "Assessed Risk (AR)", "", "",
         "Mitigations / Treatments Needed", "Residual Risk (RR)", "", ""],
        ["NR", "Hazard Description", "Likelihood", "Severity",
         "Risk Level", "Mitigations", "Likelihood", "Severity", "Risk Level"]
    ]
    for idx, mh in enumerate(hazards, start=1):
        h = mh.hazard
        mitigation_lines = [
            "• " + ln.strip() for ln in str(h.mitigations or "").splitlines() if ln.strip()]
        data.append([
            str(idx),
            Paragraph(h.hazard_description or "", small),
            h.before_likelihood or "",
            h.before_severity or "",
            h.before_risk_rating or "",
            Paragraph("<br/>".join(mitigation_lines), small),
            h.after_likelihood or "",
            h.after_severity or "",
            h.after_risk_rating or ""
        ])
    table = Table(data, colWidths=hazard_colWidths, repeatRows=2)
    ts = TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.4, colors.black),
        ('SPAN', (2, 0), (4, 0)), ('SPAN', (6, 0), (8, 0)),
        ('SPAN', (1, 0), (1, 1)), ('SPAN', (5, 0),
                                   (5, 1)), ('SPAN', (0, 0), (0, 1)),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (5, 2), (5, -1), 'LEFT'),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('BACKGROUND', (0, 1), (-1, 1), colors.lightgrey),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ])
    for row_idx, mh in enumerate(hazards, start=2):
        h = mh.hazard
        ts.add('BACKGROUND', (4, row_idx), (4, row_idx), risk_color(
            h.before_likelihood, h.before_severity, h.before_risk_rating))
        ts.add('BACKGROUND', (8, row_idx), (8, row_idx), risk_color(
            h.after_likelihood, h.after_severity, h.after_risk_rating))
    table.setStyle(ts)
    elements.append(table)

    # === SUMMARY ROW ===
    pct = form.total_percent or 0
    summary_style = ParagraphStyle(
        "summary_bold", parent=styles["Normal"],
        fontSize=10, leading=13, alignment=1
    )
    summary_data = [[
        Paragraph(
            f"<b>Total RR/Max Risk x 100 = Risk% __{pct:.0f}%__</b>", summary_style),
        Paragraph("<b>MANAGEMENT</b>", summary_style)
    ]]
    summary_table = Table(summary_data, colWidths=[350, 375])
    summary_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.4, colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    elements.append(summary_table)

    # === AUTHORITY TABLE WITH NAME AND SIGNATURE COLUMNS ===
    # Get authority signature with smaller size
    authority_sig = get_signature_image(
        authority_user, form.authority_approved, form.authority_approval_date, width=80, height=25)

    # Create centered style for name and date
    centered_small = ParagraphStyle(
        "centered_small", parent=styles["Normal"], fontSize=9, leading=11, alignment=1
    )

    # Format name and date/time for authority with centered alignment
    authority_name_date = ""
    if authority_user and form.authority_approved:
        authority_name_date = f"{authority_user.get_full_name()}<br/>{form.authority_approval_date.strftime('%d %B %Y %H:%M') if form.authority_approval_date else 'Not Signed'}"
    elif authority_user:
        authority_name_date = f"{authority_user.get_full_name()}<br/>Pending Approval"
    else:
        authority_name_date = "Not Assigned<br/>Pending Approval"

    authority_data = [
        ["Residual Risk /Max Risk (%)", "Mission Decision Authority",
         "Name with Date/Time", "Signature"],
        ["≤50%", "Operator",
         Paragraph(authority_name_date, centered_small) if pct <= 50 else "",
         authority_sig if pct <= 50 else ""],
        ["51–65%", "Supervisor",
         Paragraph(authority_name_date,
                   centered_small) if 51 <= pct <= 65 else "",
         authority_sig if 51 <= pct <= 65 else ""],
        ["66–75%", "Squadron Commander",
         Paragraph(authority_name_date,
                   centered_small) if 66 <= pct <= 75 else "",
         authority_sig if 66 <= pct <= 75 else ""],
        ["76–85%", "Director for Operations",
         Paragraph(authority_name_date,
                   centered_small) if 76 <= pct <= 85 else "",
         authority_sig if 76 <= pct <= 85 else ""],
        ["86–100%", "Commander",
         Paragraph(authority_name_date, centered_small) if pct >= 86 else "",
         authority_sig if pct >= 86 else ""]
    ]

    # Calculate column widths to match total table width of 725
    authority_colWidths = [150, 200, 200, 175]  # total = 725

    authority_table = Table(authority_data, colWidths=authority_colWidths)
    authority_style = TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.4, colors.black),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
    ])

    # Highlight the current risk level
    if pct <= 50:
        authority_style.add('BACKGROUND', (0, 1), (3, 1), colors.lightblue)
    elif 51 <= pct <= 65:
        authority_style.add('BACKGROUND', (0, 2), (3, 2), colors.lightblue)
    elif 66 <= pct <= 75:
        authority_style.add('BACKGROUND', (0, 3), (3, 3), colors.lightblue)
    elif 76 <= pct <= 85:
        authority_style.add('BACKGROUND', (0, 4), (3, 4), colors.lightblue)
    else:
        authority_style.add('BACKGROUND', (0, 5), (3, 5), colors.lightblue)

    authority_table.setStyle(authority_style)
    elements.append(authority_table)

    # === RISK MATRIX LEGEND ===
    img_path = os.path.join(app.static_folder, "risk_matrix.png")
    if os.path.exists(img_path):
        elements.append(Spacer(1, 12))
        elements.append(Paragraph("<b>Risk Matrix Legend:</b>", small))
        elements.append(Image(img_path, width=360, height=180))

    # === BUILD PDF ===
    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()

    response = make_response(pdf)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"inline; filename=mrm_{form.mrm_number}.pdf"
    return response


@app.route('/filter_hazards')
@login_required
def filter_hazards():
    activity_code = request.args.get('activity_code', 'All')
    unit = request.args.get('unit', '')

    user = get_current_user()
    if user.authority == 'Administrator':
        query = HazardRegistry.query
    else:
        query = HazardRegistry.query.filter_by(unit=user.unit)

    if activity_code != 'All':
        query = query.filter_by(activity_code=activity_code)

    hazards = query.all()

    hazard_list = []
    for hazard in hazards:
        hazard_list.append({
            'id': hazard.id,
            'activity_code': hazard.activity_code,
            'hazard_description': hazard.hazard_description,
            'after_risk_rating': hazard.after_risk_rating,
            'risk_color': hazard.get_risk_color(hazard.after_risk_rating)
        })

    return jsonify(hazard_list)


@app.route('/upload_signature', methods=['GET', 'POST'])
@login_required
def upload_signature():
    user = get_current_user()

    if request.method == 'POST':
        if 'signature' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)

        file = request.files['signature']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            if user.signature_filename:
                old_path = os.path.join(
                    app.config['SIGNATURE_FOLDER'], user.signature_filename)
                if os.path.exists(old_path):
                    os.remove(old_path)

            filename = f"signature_{user.id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.png"
            filepath = os.path.join(app.config['SIGNATURE_FOLDER'], filename)
            file.save(filepath)

            user.signature_filename = filename
            db.session.commit()

            flash('Signature uploaded successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid file type. Please upload a PNG image.', 'danger')

    return render_template('upload_signature.html')


@app.route('/signature/<filename>')
@login_required
def get_signature(filename):
    return send_file(os.path.join(app.config['SIGNATURE_FOLDER'], filename))


@app.route('/reports')
@admin_required
def reports():
    return render_template('reports.html')

# Database maintenance and migration routes


@app.route('/fix-mrm-numbers')
@admin_required
def fix_mrm_numbers():
    """Emergency fix for MRM numbers - run this once then remove the route"""
    try:
        forms_without_numbers = MRMForm.query.filter(
            MRMForm.mrm_number.is_(None)).all()

        for form in forms_without_numbers:
            # Generate new MRM number without + symbol
            date_part = form.date_created.strftime('%Y%m%d')
            same_day_forms = MRMForm.query.filter(
                db.func.date(MRMForm.date_created) == form.date_created.date(),
                MRMForm.id <= form.id
            ).count()
            number_part = f"{same_day_forms:02d}"
            form.mrm_number = f"{date_part}{number_part}"  # REMOVED + SYMBOL

        db.session.commit()
        flash(
            f'Fixed MRM numbers for {len(forms_without_numbers)} forms', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error fixing MRM numbers: {str(e)}', 'danger')

    return redirect(url_for('index'))


@app.route('/verify-supervisor-migration')
@admin_required
def verify_supervisor_migration():
    """Verify that all Supervisor/OIC values have been migrated to Supervisor"""
    try:
        with db.engine.connect() as conn:
            # Check for any remaining Supervisor/OIC values
            result = conn.execute(db.text("""
                SELECT COUNT(*) as count FROM mrm_form 
                WHERE authority_level = 'Supervisor/OIC'
            """))
            mrm_count = result.fetchone()[0]

            result = conn.execute(db.text("""
                SELECT COUNT(*) as count FROM unit_authority 
                WHERE authority_level = 'Supervisor/OIC'
            """))
            unit_auth_count = result.fetchone()[0]

            if mrm_count == 0 and unit_auth_count == 0:
                flash(
                    'All Supervisor/OIC values have been successfully migrated to Supervisor!', 'success')
            else:
                flash(
                    f'Found {mrm_count} mrm_form and {unit_auth_count} unit_authority records still using Supervisor/OIC', 'warning')

    except Exception as e:
        flash(f'Error verifying migration: {str(e)}', 'danger')

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
