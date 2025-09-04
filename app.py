from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

from config import Config
from extensions import db
from forms import LoginForm, PolicyForm, RiskForm, RegistrationForm
from models import User, Policy, Risk, AuditLog

# Initialize app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create DB tables if not exist
with app.app_context():
    db.create_all()

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    policies = Policy.query.order_by(Policy.timestamp.desc()).all()
    return render_template('dashboard.html', policies=policies)

@app.route('/create_policy', methods=['GET', 'POST'])
@login_required
def create_policy():
    form = PolicyForm()
    if form.validate_on_submit():
        policy = Policy(
            title=form.title.data,
            content=form.content.data,
            iso_section=form.iso_section.data,
            nist_category=form.nist_category.data,
            created_by=current_user.username,
            user_id=current_user.id
        )
        db.session.add(policy)

        log = AuditLog(
            action=f"Created policy: {form.title.data}",
            user=current_user  # Relationship, not string
        )
        db.session.add(log)

        db.session.commit()
        flash('Policy created successfully!')
        return redirect(url_for('dashboard'))
    return render_template('create_policy.html', form=form)

@app.route('/risk_register', methods=['GET', 'POST'])
@login_required
def risk_register():
    form = RiskForm()
    if form.validate_on_submit():
        risk = Risk(
            title=form.title.data,
            category=form.category.data,
            impact=form.impact.data,
            likelihood=form.likelihood.data,
            mitigation=form.mitigation.data,
            status=form.status.data
        )
        db.session.add(risk)

        log = AuditLog(
            action=f"Added risk: {form.title.data}",
            user=current_user
        )
        db.session.add(log)

        db.session.commit()
        flash('Risk added successfully!')
        return redirect(url_for('risk_register'))

    risks = Risk.query.order_by(Risk.created_at.desc()).all()
    return render_template('risk_register.html', form=form, risks=risks)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_pw, role=form.role.data)
        db.session.add(new_user)
        db.session.commit()

        log = AuditLog(
            action=f"Registered new user: {form.username.data}",
            user=new_user
        )
        db.session.add(log)
        db.session.commit()

        flash('Account created successfully! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/audit_logs')
@login_required
def audit_logs():
    if current_user.role != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('index'))
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('audit_logs.html', logs=logs)

@app.route('/delete_policy/<int:policy_id>', methods=['POST'])
@login_required
def delete_policy(policy_id):
    policy = Policy.query.get_or_404(policy_id)

    # Restrict deletion to owner or admin
    if policy.user_id != current_user.id and current_user.role != 'admin':
        abort(403)

    db.session.delete(policy)

    log = AuditLog(
        action=f"Deleted policy: {policy.title}",
        user=current_user
    )
    db.session.add(log)

    db.session.commit()
    flash('Policy has been deleted.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/create_admin')
def create_admin():
    if User.query.filter_by(username='admin').first():
        return 'Admin already exists.'
    admin = User(
        username='admin',
        password=generate_password_hash('admin123'),
        role='admin'
    )
    db.session.add(admin)
    db.session.commit()
    return 'Admin user created. Username: admin, Password: admin123'

# --- Run the app ---
if __name__ == '__main__':
    app.run(debug=True)
