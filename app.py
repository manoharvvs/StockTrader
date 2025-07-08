from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import uuid
from datetime import datetime
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler

# Initialize Flask app
app = Flask(__name__)

###################################################################
## -------------------- Configurations ------------------------- ##
###################################################################

# Security configuration
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-secret-key-please-change-in-production'

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
db_dir = os.path.join(basedir, 'db')
os.makedirs(db_dir, exist_ok=True)
db_path = os.path.join(db_dir, 'stocker.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

################################################################
## ---------------------- Models ----------------------------- ##
################################################################

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='trader')
    active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    transactions = db.relationship('Transaction', backref='user', lazy=True)
    portfolio_items = db.relationship('Portfolio', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Stock(db.Model):
    __tablename__ = 'stocks'
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    current_price = db.Column(db.Float, nullable=False)
    market_cap = db.Column(db.Float)
    sector = db.Column(db.String(100))
    industry = db.Column(db.String(100))
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    transactions = db.relationship('Transaction', backref='stock', lazy=True)
    portfolio_items = db.relationship('Portfolio', backref='stock', lazy=True)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stocks.id'), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # 'buy' or 'sell'
    quantity = db.Column(db.Integer, nullable=False)
    price_per_share = db.Column(db.Float, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

class Portfolio(db.Model):
    __tablename__ = 'portfolio'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stocks.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    average_cost = db.Column(db.Float, nullable=False)
    current_value = db.Column(db.Float)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

###################################################################
## ----------------------- Decorators ------------------------- ##
###################################################################

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login', next=request.url))
            if session.get('role') != role:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

###################################################################
## ----------------------- Functions -------------------------- ##
###################################################################

def create_demo_data():
    """Initialize database with demo data"""
    try:
        # Create demo users
        admin = User(
            username='admin_demo',
            email='admin@stocker.com',
            role='admin',
            active=True
        )
        admin.set_password('Admin@123')
        
        trader = User(
            username='trader_demo',
            email='trader@stocker.com',
            role='trader',
            active=True
        )
        trader.set_password('Trader@123')
        
        # Create demo stocks
        stocks = [
            Stock(symbol='AAPL', name='Apple Inc.', current_price=145.86, market_cap=2.4e12, sector='Technology', industry='Consumer Electronics'),
            Stock(symbol='GOOGL', name='Alphabet Inc.', current_price=2752.88, market_cap=1.8e12, sector='Technology', industry='Internet Content'),
            Stock(symbol='MSFT', name='Microsoft Corporation', current_price=299.35, market_cap=2.2e12, sector='Technology', industry='Software'),
            Stock(symbol='AMZN', name='Amazon.com Inc.', current_price=3285.03, market_cap=1.7e12, sector='Consumer Cyclical', industry='Internet Retail'),
            Stock(symbol='TSLA', name='Tesla Inc.', current_price=685.70, market_cap=700e9, sector='Consumer Cyclical', industry='Auto Manufacturers')
        ]
        
        db.session.add_all([admin, trader])
        db.session.add_all(stocks)
        db.session.commit()
        app.logger.info("Demo data created successfully")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating demo data: {str(e)}")

###################################################################
## ----------------------- Routes ------------------------------ ##
###################################################################

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            email = request.form.get('email', '').lower().strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            role = request.form.get('role', 'trader')

            # Validate inputs
            if not all([first_name, last_name, email, password, confirm_password]):
                flash('All fields are required.', 'danger')
                return redirect(url_for('signup'))
            
            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return redirect(url_for('signup'))
            
            if len(password) < 8:
                flash('Password must be at least 8 characters long.', 'danger')
                return redirect(url_for('signup'))
            
            # Generate username
            username = f"{first_name}_{last_name}".lower()
            
            # Check if user exists
            if User.query.filter((User.email == email) | (User.username == username)).first():
                flash('Email or username already exists.', 'warning')
                return redirect(url_for('signup'))
            
            # Create user
            new_user = User(
                username=username,
                email=email,
                role=role
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            # Automatically log the user in after signup
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            session['role'] = new_user.role
            
            flash('Account created successfully! Welcome!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to appropriate dashboard
        
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Signup error: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('signup'))
    
    return render_template('signup.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').lower().strip()
            password = request.form.get('password', '')
            remember_me = request.form.get('remember_me', False)
            
            user = User.query.filter_by(email=email, active=True).first()
            
            if user and user.check_password(password):
                session['user_id'] = user.id
                session['username'] = user.username
                session['role'] = user.role
                session.permanent = remember_me
                
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                flash('Login successful!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Invalid email or password.', 'danger')
                return redirect(url_for('login'))
        
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login. Please try again.', 'danger')
            return redirect(url_for('login'))
    
    return render_template("login.html")

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('trader_dashboard'))
    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard', 'danger')
        return redirect(url_for('index'))
    
@app.route('/custom-login', methods=['GET', 'POST'])
def custom_login():
    if request.method == 'POST':
        identifier = request.form.get('identifier')  # Could be email or username
        password = request.form.get('password')
        
        # Check if identifier is email or username
        if '@' in identifier:
            user = User.query.filter_by(email=identifier).first()
        else:
            user = User.query.filter_by(username=identifier).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            
            # Custom redirect logic
            if user.some_custom_field:
                return redirect(url_for('custom_destination'))
            else:
                return redirect(url_for('default_destination'))
        
        flash('Invalid credentials', 'danger')
    
    return render_template('custom_login.html')


@app.route('/trader/dashboard')
@login_required
@role_required('trader')
def trader_dashboard():
    try:
        user = User.query.get(session['user_id'])
        stocks = Stock.query.order_by(Stock.symbol).all()
        portfolio = Portfolio.query.filter_by(user_id=user.id).all()
        
        return render_template(
            "trader_dashboard.html",
            user=user,
            stocks=stocks,
            portfolio=portfolio
        )
    except Exception as e:
        app.logger.error(f"Trader dashboard error: {str(e)}")
        flash('Error loading trader dashboard', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    try:
        users = User.query.order_by(User.created_at.desc()).limit(10).all()
        stocks = Stock.query.order_by(Stock.last_updated.desc()).limit(10).all()
        transactions = Transaction.query.order_by(Transaction.created_at.desc()).limit(10).all()
        
        return render_template(
            'admin_dashboard.html',
            users=users,
            stocks=stocks,
            transactions=transactions
        )
    except Exception as e:
        app.logger.error(f"Admin dashboard error: {str(e)}")
        flash('Error loading admin dashboard', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/transactions')
@login_required
def transaction_history():
    try:
        transactions = Transaction.query.filter_by(user_id=session['user_id'])\
            .order_by(Transaction.created_at.desc())\
            .all()
        return render_template("transaction_history.html", transactions=transactions)
    except Exception as e:
        app.logger.error(f"Transaction history error: {str(e)}")
        flash('Error loading transaction history', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/portfolio')
@login_required
def portfolio_overview():
    try:
        portfolio = Portfolio.query.filter_by(user_id=session['user_id'])\
            .join(Stock)\
            .add_columns(
                Stock.symbol,
                Stock.name,
                Stock.current_price,
                Portfolio.quantity,
                Portfolio.average_cost,
                Portfolio.current_value
            )\
            .all()
        
        total_value = sum(item.current_value for item in portfolio if item.current_value)
        
        return render_template(
            "portfolio_overview.html",
            portfolio=portfolio,
            total_value=total_value
        )
    except Exception as e:
        app.logger.error(f"Portfolio overview error: {str(e)}")
        flash('Error loading portfolio', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/market')
@login_required
def market_trading():
    try:
        stocks = Stock.query.order_by(Stock.symbol).all()
        return render_template("market_trading.html", stocks=stocks)
    except Exception as e:
        app.logger.error(f"Market trading error: {str(e)}")
        flash('Error loading market data', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    try:
        user = User.query.get(session['user_id'])
        
        if request.method == 'POST':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not user.check_password(current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('profile'))
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('profile'))
            
            if len(new_password) < 8:
                flash('Password must be at least 8 characters', 'danger')
                return redirect(url_for('profile'))
            
            user.set_password(new_password)
            db.session.commit()
            flash('Password updated successfully', 'success')
            return redirect(url_for('profile'))
        
        return render_template("profile.html", user=user)
    except Exception as e:
        app.logger.error(f"Profile error: {str(e)}")
        flash('Error accessing profile', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    try:
        session.clear()
        flash('You have been logged out successfully.', 'success')
    except Exception as e:
        app.logger.error(f"Logout error: {str(e)}")
        flash('Error during logout', 'danger')
    finally:
        return redirect(url_for('index'))

# Static pages
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
@app.errorhandler(400)
def bad_request(e):
    return render_template('errors/400.html'), 400

@app.errorhandler(401)
def unauthorized(e):
    return render_template('errors/401.html'), 401

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    db.session.rollback()
    return render_template('errors/500.html'), 500

###################################################################
## ----------------------- Initialization ---------------------- ##
###################################################################

def initialize_app():
    with app.app_context():
        try:
            db.create_all()
            
            # Check if demo data needs to be created
            if not User.query.first():
                create_demo_data()
                app.logger.info("Database initialized with demo data")
            else:
                app.logger.info("Database already initialized")
        except Exception as e:
            app.logger.error(f"Initialization error: {str(e)}")
            raise

if __name__ == '__main__':
    initialize_app()
    app.run(debug=True, host='0.0.0.0', port=5000)

