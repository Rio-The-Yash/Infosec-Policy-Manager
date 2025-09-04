
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError

# ISO 27001 Options
ISO_CATEGORIES = [
    ('A.5', 'A.5: Information Security Policies'),
    ('A.6', 'A.6: Organization of Information Security'),
    ('A.9', 'A.9: Access Control'),
    ('A.12', 'A.12: Operations Security'),
    ('A.16', 'A.16: Information Security Incident Management'),
    # Add more as needed
]

# NIST CSF Options
NIST_CATEGORIES = [
    ('ID.AM', 'ID.AM: Asset Management'),
    ('PR.AC', 'PR.AC: Access Control'),
    ('PR.PT', 'PR.PT: Protective Technology'),
    ('DE.CM', 'DE.CM: Security Continuous Monitoring'),
    ('RS.RP', 'RS.RP: Response Planning'),
    # Add more as needed
]

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PolicyForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    iso_section = SelectField('ISO 27001 Section', choices=ISO_CATEGORIES)
    nist_category = SelectField('NIST CSF Category', choices=NIST_CATEGORIES)
    submit = SubmitField('Create Policy')

class RiskForm(FlaskForm):
    title = StringField('Risk Title', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('Operational', 'Operational'),
        ('Strategic', 'Strategic'),
        ('Compliance', 'Compliance'),
        ('Reputational', 'Reputational')
    ])
    impact = SelectField('Impact', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')])
    likelihood = SelectField('Likelihood', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')])
    mitigation = TextAreaField('Mitigation Steps')
    status = SelectField('Status', choices=[('Open', 'Open'), ('In Progress', 'In Progress'), ('Resolved', 'Resolved')])
    submit = SubmitField('Add Risk')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')], default='user')
    submit = SubmitField('Register')

    def validate_username(self, username):
        from models import User
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')
