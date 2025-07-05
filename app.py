# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
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

###################################################################
## -------------------- Configurations ------------------------- ##
###################################################################



# Database config
basedir = os.path.abspath(os.path.dirname(__file__))
# Check if db directory exists, if not create it
db_dir = os.path.join(basedir, 'db')
if not os.path.exists(db_dir):
    os.makedirs(db_dir)

db_path = os.path.join(db_dir, 'stocker.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Add a print statement to debug
print(f"Connecting to database at: {db_path}")

db = SQLAlchemy(app)

################################################################
## ---------------------- Models ----------------------------- ##
################################################################
class User(db.Model):
    __tablename__ = 'user'  # Explicitly set table name to match the database
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'admin' or 'trader'
    # Relationships
    transaction = db.relationship('Transaction', backref='user', lazy=True)
    portfolio = db.relationship('Portfolio', backref='user', lazy=True)

class Stock(db.Model):
    __tablename__ = 'stock'  # Explicitly set table name to match the database
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    price = db.Column(db.Float, nullable=False)
    market_cap = db.Column(db.Float, nullable=False)
    sector = db.Column(db.String(100), nullable=False)
    industry = db.Column(db.String(100), nullable=False)
    date_added = db.Column(db.Date, server_default=db.func.current_date())
    # Relationships
    transaction = db.relationship('Transaction', backref='stock', lazy=True)
    portfolio = db.relationship('Portfolio', backref='stock', lazy=True)

class Transaction(db.Model):
    __tablename__ = 'stock_transaction'  # Explicitly set table name to match the database
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
    action = db.Column(db.String(10), nullable=False)  # 'buy' or 'sell'
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(10), nullable=False, default='completed')  # 'pending', 'completed', 'failed'
    transaction_date = db.Column(db.DateTime, server_default=db.func.now())

class Portfolio(db.Model):
    __tablename__ = 'portfolio'  # Explicitly set table name to match the database
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    average_price = db.Column(db.Float, nullable=False)


###################################################################
## ----------------------- Functions --------------------------- ##
###################################################################
def get_user_by_email(email):
          """Get user by email"""
          table = dynamodb.Table (USER_TABLE)
          response = table.get_item(Key={'email': email})
          return response.get('Item')
      
      
      
      
      
###################################################################
## ----------------------- Routes ------------------------------ ##
###################################################################
      
      
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
          if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            role = request.form['role']

            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('User already exists. Please login.', 'warning')
                return redirect(url_for('login'))

            new_user = User(username=username, email=email, password=password, role=role)
            db.session.add(new_user)
            db.session.commit()

            flash(f"Account created for {username}", 'success')
            return redirect(url_for('login'))

          return render_template('signup.html') 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form.get('role')
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email, role=role).first()
        print(f"Trying to login with: {email} ({role})")

        if user and user.password == password:
            print("Login successful!")
            session['email'] = user.email
            session['role'] = user.role
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard_admin' if role == 'admin' else 'dashboard_trader'))
        else:
            print("Login failed.")
            flash('Invalid credentials or role mismatch.', 'danger')
            return redirect(url_for('login'))

    return render_template("login.html")

@app.route('/trader_dashboard')
def Trader_dashboard():
    if 'email' not in session or session.get('role') != 'trader':
        flash("Access denied. Traders only.", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=session['email']).first()
    stocks = Stock.query.all()
    return render_template("trader_dashboard.html",user=user, market_data=stocks)
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'email' not in session or session.get('role') != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=session['email']).first()
    stocks = Stock.query.all()
    return render_template('admin_dashboard.html', user=user, market_data=stocks)


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

@app.route('/forgot_password')
def forgot_password():
    return render_template("forgot_password.html")
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))   

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)