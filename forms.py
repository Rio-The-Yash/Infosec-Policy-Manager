from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PolicyForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    iso_section = StringField('ISO Section')
    nist_category = StringField('NIST Category')
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
