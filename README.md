---

# Information Security Policy Management System

A lightweight web-based application designed to create, manage, and track ISO 27001-style information security policies and risk registers. Built with Flask, SQLite, and Bootstrap, this project provides role-based access, audit logging, and compliance mapping based on industry security frameworks like ISO 27001 and NIST CSF.

---

## Table of Contents

* [Features](#features)
* [Technologies Used](#technologies-used)
* [Installation](#installation)
* [Usage](#usage)
* [Project Structure](#project-structure)
* [Database Models](#database-models)
* [Security](#security)
* [Future Enhancements](#future-enhancements)
* [Contributing](#contributing)

---

## Features

* User Authentication & Role-based Access Control
* Create, view, and manage security policies
* Maintain a risk register with risk categorization, impact, likelihood, mitigation, and status
* Audit logging for tracking user actions
* Policy compliance mapping with ISO 27001 and NIST CSF references
* Responsive design using Bootstrap
* Admin user creation route for easy setup

---

## Technologies Used

* Python 3.x
* Flask (Web Framework)
* Flask-SQLAlchemy (ORM)
* Flask-WTF (Forms & Validation)
* Flask-Login (Authentication)
* SQLite (Database)
* Bootstrap (Frontend CSS Framework)
* Werkzeug (Password hashing)

---

## Installation

### Prerequisites

* Python 3.8+
* Git

### Steps

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Rio-The-Yash/infosec-policy-manager.git
   cd infosec-policy-manager
   ```

2. **Create and activate a virtual environment:**

   On macOS/Linux:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

   On Windows (PowerShell):

   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database:**

   ```bash
   flask shell
   >>> from models import db
   >>> db.create_all()
   >>> exit()
   ```

5. **Create an admin user (optional):**

   Start the app and visit:
   `http://127.0.0.1:5000/create_admin`

---

## Usage

1. **Run the Flask app:**

   ```bash
   flask run
   ```

2. **Access the app:**

   Open your browser at `http://127.0.0.1:5000`

3. **Login:**

   * Use the admin credentials created via `/create_admin` route
   * Or add users manually through the Flask shell

4. **Features:**

   * Dashboard: View all policies
   * Create new policies with compliance tags
   * Risk Register: Add and manage risks
   * Audit logs track actions by users

---

## Project Structure

```
infosec_policy_app/
│
├── app.py                 # Main Flask application and routes
├── config.py              # Configuration settings
├── forms.py               # WTForms definitions
├── models.py              # SQLAlchemy database models
├── requirements.txt       # Python dependencies
│
├── /templates             # HTML Jinja2 templates
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── create_policy.html
│   └── risk_register.html
│
└── /static
    └── style.css          # Custom CSS styles
```

---

## Database Models

* **User:** Stores user credentials and roles
* **Policy:** Security policies with ISO and NIST mappings
* **Risk:** Risk items with categories, impact, likelihood, and mitigation steps
* **AuditLog:** Tracks user actions with timestamps

---

## Security

* Passwords are securely hashed with Werkzeug
* Role-based access control to restrict features
* User actions are logged for audit purposes

---

## Future Enhancements

* User registration and management UI
* Edit/Delete functionality for policies and risks
* Export policies and risks to PDF/CSV
* Integration with external compliance tools
* Two-Factor Authentication (2FA)
* Email notifications on policy/risk changes

---

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your improvements or bug fixes.

---
