# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
import boto3
import os
import uuid
from datetime import datetime
from boto3.dynamodb.conditions import Key, Attr
from decimal import Decimal
import json
import hashlib
import re
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session management

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Process signup form data here
        # Validate inputs, create user in database, etc.
        return redirect(url_for('login'))
    return render_template("signup.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Process login form data here
        # Validate credentials, set session, etc.
        return redirect(url_for('dashboard'))
    return render_template("login.html")

@app.route('/trader_dashboard')
def Trader_dashboard():
    # Add logic to fetch trader data if needed
    return render_template("trader_dashboard.html")
@app.route('/admin_dashboard')
def admin_dashboard():
    # Add logic to fetch trader data if needed
    return render_template("admin_dashboard.html")
@app.route('/transaction_history')
def Transaction_history():
    # Add logic to fetch transaction history
    return render_template("transaction_history.html")

@app.route('/portfolio_overview')
def portfolio_overview():
    # Add logic to fetch portfolio data
    return render_template("portfolio_overview.html")

@app.route('/market_trading')
def Market_trading():
    # Add logic for market trading page
    return render_template("market_trading.html")

@app.route('/profile')
def Profile():
    # Add logic to fetch user profile
    return render_template("profile.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/contact')
def contact():
    return render_template("contact.html")

@app.route('/privacy')
def privacy():
    return render_template("privacy.html")

@app.route('/terms')
def terms():
    return render_template("terms.html")

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)