import boto3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import os
import uuid
from datetime import datetime
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
from botocore.exceptions import ClientError

# Initialize Flask app
app = Flask(__name__)

###################################################################
## -------------------- Configurations ------------------------- ##
###################################################################

# Security configuration
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-secret-key-please-change-in-production'

# AWS Configuration
app.config['AWS_REGION'] = os.environ.get('AWS_REGION', 'us-east-1')
app.config['AWS_ACCESS_KEY_ID'] = os.environ.get('AWS_ACCESS_KEY_ID')
app.config['AWS_SECRET_ACCESS_KEY'] = os.environ.get('AWS_SECRET_ACCESS_KEY')
app.config['DYNAMODB_TABLE_USERS'] = 'stocker_users'
app.config['DYNAMODB_TABLE_STOCKS'] = 'stocker_stocks'
app.config['DYNAMODB_TABLE_TRANSACTIONS'] = 'stocker_transactions'
app.config['DYNAMODB_TABLE_PORTFOLIO'] = 'stocker_portfolio'
app.config['SNS_TOPIC_ARN'] = os.environ.get('SNS_TOPIC_ARN')

# Initialize AWS clients
dynamodb = boto3.resource(
    'dynamodb',
    region_name=app.config['AWS_REGION'],
    aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
    aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY']
)

sns = boto3.client(
    'sns',
    region_name=app.config['AWS_REGION'],
    aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
    aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY']
)

# Initialize DynamoDB tables
try:
    users_table = dynamodb.Table(app.config['DYNAMODB_TABLE_USERS'])
    stocks_table = dynamodb.Table(app.config['DYNAMODB_TABLE_STOCKS'])
    transactions_table = dynamodb.Table(app.config['DYNAMODB_TABLE_TRANSACTIONS'])
    portfolio_table = dynamodb.Table(app.config['DYNAMODB_TABLE_PORTFOLIO'])
except ClientError as e:
    print(f"Error connecting to DynamoDB: {e}")
    raise

# Configure logging
logging.basicConfig(level=logging.INFO)
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

################################################################
## ---------------------- Helper Functions ------------------- ##
################################################################

def create_dynamo_tables():
    """Create DynamoDB tables if they don't exist"""
    try:
        tables = dynamodb.meta.client.list_tables()['TableNames']
        
        if app.config['DYNAMODB_TABLE_USERS'] not in tables:
            dynamodb.create_table(
                TableName=app.config['DYNAMODB_TABLE_USERS'],
                KeySchema=[{'AttributeName': 'user_id', 'KeyType': 'HASH'}],
                AttributeDefinitions=[{'AttributeName': 'user_id', 'AttributeType': 'S'}],
                ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            )
        
        if app.config['DYNAMODB_TABLE_STOCKS'] not in tables:
            dynamodb.create_table(
                TableName=app.config['DYNAMODB_TABLE_STOCKS'],
                KeySchema=[{'AttributeName': 'stock_id', 'KeyType': 'HASH'}],
                AttributeDefinitions=[{'AttributeName': 'stock_id', 'AttributeType': 'S'}],
                ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            )
        
        if app.config['DYNAMODB_TABLE_TRANSACTIONS'] not in tables:
            dynamodb.create_table(
                TableName=app.config['DYNAMODB_TABLE_TRANSACTIONS'],
                KeySchema=[{'AttributeName': 'transaction_id', 'KeyType': 'HASH'}],
                AttributeDefinitions=[{'AttributeName': 'transaction_id', 'AttributeType': 'S'}],
                ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            )
        
        if app.config['DYNAMODB_TABLE_PORTFOLIO'] not in tables:
            dynamodb.create_table(
                TableName=app.config['DYNAMODB_TABLE_PORTFOLIO'],
                KeySchema=[
                    {'AttributeName': 'user_id', 'KeyType': 'HASH'},
                    {'AttributeName': 'stock_id', 'KeyType': 'RANGE'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'user_id', 'AttributeType': 'S'},
                    {'AttributeName': 'stock_id', 'AttributeType': 'S'}
                ],
                ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            )
            
    except ClientError as e:
        app.logger.error(f"Error creating DynamoDB tables: {e}")
        raise

def send_sns_notification(subject, message):
    """Send notification via AWS SNS"""
    try:
        response = sns.publish(
            TopicArn=app.config['SNS_TOPIC_ARN'],
            Message=message,
            Subject=subject
        )
        app.logger.info(f"SNS notification sent: {response['MessageId']}")
    except ClientError as e:
        app.logger.error(f"Error sending SNS notification: {e}")

def create_demo_data():
    """Initialize database with demo data"""
    try:
        # Create demo users
        admin_user = {
            'user_id': str(uuid.uuid4()),
            'username': 'admin_demo',
            'email': 'admin@stocker.com',
            'password_hash': generate_password_hash('Admin@123'),
            'role': 'admin',
            'active': True,
            'created_at': datetime.utcnow().isoformat(),
            'last_login': None
        }
        
        trader_user = {
            'user_id': str(uuid.uuid4()),
            'username': 'trader_demo',
            'email': 'trader@stocker.com',
            'password_hash': generate_password_hash('Trader@123'),
            'role': 'trader',
            'active': True,
            'created_at': datetime.utcnow().isoformat(),
            'last_login': None
        }
        
        # Put demo users in DynamoDB
        users_table.put_item(Item=admin_user)
        users_table.put_item(Item=trader_user)
        
        # Create demo stocks
        demo_stocks = [
            {
                'stock_id': str(uuid.uuid4()),
                'symbol': 'AAPL',
                'name': 'Apple Inc.',
                'current_price': 145.86,
                'market_cap': 2.4e12,
                'sector': 'Technology',
                'industry': 'Consumer Electronics',
                'last_updated': datetime.utcnow().isoformat()
            },
            {
                'stock_id': str(uuid.uuid4()),
                'symbol': 'GOOGL',
                'name': 'Alphabet Inc.',
                'current_price': 2752.88,
                'market_cap': 1.8e12,
                'sector': 'Technology',
                'industry': 'Internet Content',
                'last_updated': datetime.utcnow().isoformat()
            },
            {
                'stock_id': str(uuid.uuid4()),
                'symbol': 'MSFT',
                'name': 'Microsoft Corporation',
                'current_price': 299.35,
                'market_cap': 2.2e12,
                'sector': 'Technology',
                'industry': 'Software',
                'last_updated': datetime.utcnow().isoformat()
            }
        ]
        
        # Put demo stocks in DynamoDB
        for stock in demo_stocks:
            stocks_table.put_item(Item=stock)
        
        app.logger.info("Demo data created successfully")
        
    except ClientError as e:
        app.logger.error(f"Error creating demo data: {e}")
        raise

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
            response = users_table.scan(
                FilterExpression='email = :email OR username = :username',
                ExpressionAttributeValues={
                    ':email': email,
                    ':username': username
                }
            )
            
            if response.get('Items'):
                flash('Email or username already exists.', 'warning')
                return redirect(url_for('signup'))
            
            # Create user
            new_user = {
                'user_id': str(uuid.uuid4()),
                'username': username,
                'email': email,
                'password_hash': generate_password_hash(password),
                'role': role,
                'active': True,
                'created_at': datetime.utcnow().isoformat(),
                'last_login': None,
                'first_name': first_name,
                'last_name': last_name
            }
            
            users_table.put_item(Item=new_user)
            
            # Send welcome email via SNS
            send_sns_notification(
                subject="Welcome to Stocker!",
                message=f"Hello {first_name},\n\nThank you for registering with Stocker. Your account has been created successfully.\n\nUsername: {username}\n\nPlease login to access your account."
            )
            
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))  # Redirect to login page after signup
        
        except ClientError as e:
            app.logger.error(f"Signup error: {e}")
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
            
            # Get user from DynamoDB
            response = users_table.scan(
                FilterExpression='email = :email AND active = :active',
                ExpressionAttributeValues={
                    ':email': email,
                    ':active': True
                }
            )
            
            users = response.get('Items', [])
            
            if users and check_password_hash(users[0]['password_hash'], password):
                user = users[0]
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['role'] = user['role']
                session.permanent = remember_me
                
                # Update last login
                users_table.update_item(
                    Key={'user_id': user['user_id']},
                    UpdateExpression='SET last_login = :last_login',
                    ExpressionAttributeValues={
                        ':last_login': datetime.utcnow().isoformat()
                    }
                )
                
                flash('Login successful!', 'success')
                next_page = request.args.get('next')
                
                # Redirect based on role
                if user['role'] == 'admin':
                    return redirect(next_page or url_for('admin_dashboard'))
                else:
                    return redirect(next_page or url_for('trader_dashboard'))
            else:
                flash('Invalid email or password.', 'danger')
                return redirect(url_for('login'))
        
        except ClientError as e:
            app.logger.error(f"Login error: {e}")
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
        app.logger.error(f"Dashboard error: {e}")
        flash('Error loading dashboard', 'danger')
        return redirect(url_for('index'))

@app.route('/trader/dashboard')
@login_required
@role_required('trader')
def trader_dashboard():
    try:
        # Get user portfolio
        response = portfolio_table.query(
            KeyConditionExpression='user_id = :user_id',
            ExpressionAttributeValues={':user_id': session['user_id']}
        )
        portfolio = response.get('Items', [])
        
        # Get all stocks
        stocks = stocks_table.scan().get('Items', [])
        
        return render_template(
            "trader_dashboard.html",
            user_id=session['user_id'],
            username=session['username'],
            stocks=stocks,
            portfolio=portfolio
        )
    except ClientError as e:
        app.logger.error(f"Trader dashboard error: {e}")
        flash('Error loading trader dashboard', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    try:
        # Get recent users
        users = users_table.scan(
            Limit=10,
            ProjectionExpression='user_id, username, email, role, created_at'
        ).get('Items', [])
        
        # Get recent stocks
        stocks = stocks_table.scan(
            Limit=10,
            ProjectionExpression='stock_id, symbol, name, current_price, last_updated'
        ).get('Items', [])
        
        # Get recent transactions
        transactions = transactions_table.scan(
            Limit=10,
            ProjectionExpression='transaction_id, user_id, stock_id, type, quantity, created_at'
        ).get('Items', [])
        
        return render_template(
            'admin_dashboard.html',
            users=users,
            stocks=stocks,
            transactions=transactions
        )
    except ClientError as e:
        app.logger.error(f"Admin dashboard error: {e}")
        flash('Error loading admin dashboard', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/transactions')
@login_required
def transaction_history():
    try:
        transactions = transactions_table.scan(
            FilterExpression='user_id = :user_id',
            ExpressionAttributeValues={':user_id': session['user_id']}
        ).get('Items', [])
        
        return render_template("transaction_history.html", transactions=transactions)
    except ClientError as e:
        app.logger.error(f"Transaction history error: {e}")
        flash('Error loading transaction history', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/portfolio')
@login_required
def portfolio_overview():
    try:
        # Get portfolio items
        response = portfolio_table.query(
            KeyConditionExpression='user_id = :user_id',
            ExpressionAttributeValues={':user_id': session['user_id']}
        )
        portfolio = response.get('Items', [])
        
        # Calculate total portfolio value
        total_value = sum(float(item.get('current_value', 0)) for item in portfolio)
        
        return render_template(
            "portfolio_overview.html",
            portfolio=portfolio,
            total_value=total_value
        )
    except ClientError as e:
        app.logger.error(f"Portfolio overview error: {e}")
        flash('Error loading portfolio', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/market')
@login_required
def market_trading():
    try:
        stocks = stocks_table.scan().get('Items', [])
        return render_template("market_trading.html", stocks=stocks)
    except ClientError as e:
        app.logger.error(f"Market trading error: {e}")
        flash('Error loading market data', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    try:
        if request.method == 'POST':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            # Get user from DynamoDB
            response = users_table.get_item(Key={'user_id': session['user_id']})
            user = response.get('Item')
            
            if not user or not check_password_hash(user['password_hash'], current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('profile'))
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('profile'))
            
            if len(new_password) < 8:
                flash('Password must be at least 8 characters', 'danger')
                return redirect(url_for('profile'))
            
            # Update password
            users_table.update_item(
                Key={'user_id': session['user_id']},
                UpdateExpression='SET password_hash = :password_hash',
                ExpressionAttributeValues={
                    ':password_hash': generate_password_hash(new_password)
                }
            )
            
            flash('Password updated successfully', 'success')
            return redirect(url_for('profile'))
        
        # Get user details
        response = users_table.get_item(Key={'user_id': session['user_id']})
        user = response.get('Item')
        
        return render_template("profile.html", user=user)
    except ClientError as e:
        app.logger.error(f"Profile error: {e}")
        flash('Error accessing profile', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    try:
        session.clear()
        flash('You have been logged out successfully.', 'success')
    except Exception as e:
        app.logger.error(f"Logout error: {e}")
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
    return render_template('errors/500.html'), 500

###################################################################
## ----------------------- Initialization ---------------------- ##
###################################################################

def initialize_app():
    try:
        # Create tables if they don't exist
        create_dynamo_tables()
        
        # Check if demo data needs to be created
        response = users_table.scan(Select='COUNT')
        if response.get('Count', 0) == 0:
            create_demo_data()
            app.logger.info("Database initialized with demo data")
        else:
            app.logger.info("Database already initialized")
    except ClientError as e:
        app.logger.error(f"Initialization error: {e}")
        raise

if __name__ == '__main__':
    initialize_app()
    app.run(debug=True, host='0.0.0.0', port=5000)