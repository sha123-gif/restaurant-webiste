from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, FloatField, SelectField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, NumberRange
from datetime import datetime
import os

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)

class Bill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_name = db.Column(db.String(100), nullable=False)
    order_type = db.Column(db.String(20), nullable=False)  # 'dine-in' or 'takeaway'
    table_no = db.Column(db.String(20), nullable=True)  # Optional, for dine-in orders
    quantity = db.Column(db.Integer, nullable=False, default=1)
    amount = db.Column(db.Float, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Branch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    contact_number = db.Column(db.String(15), nullable=False)
    contact_person = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class BillingForm(FlaskForm):
    order_name = StringField('Order Name', validators=[DataRequired()])
    order_type = SelectField('Order Type', choices=[('dine-in', 'Dine-In'), ('takeaway', 'Takeaway')], validators=[DataRequired()])
    table_no = StringField('Table Number', validators=[Length(max=20)])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)], default=1)
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField('Add Bill')

class BranchForm(FlaskForm):
    name = StringField('Branch Name', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    pincode = StringField('Pincode', validators=[DataRequired()])
    contact_number = StringField('Contact Number', validators=[DataRequired()])
    contact_person = StringField('Contact Person', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Add Branch')

# Routes
@app.route("/")
@app.route("/home")
def home():
    branches = Branch.query.all()
    return render_template('index.html', branches=branches)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('billing'))  # Redirect to billing page after login
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('billing'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/billing", methods=['GET', 'POST'])
@login_required
def billing():
    form = BillingForm()
    if form.validate_on_submit():
        bill = Bill(
            order_name=form.order_name.data,
            order_type=form.order_type.data,
            table_no=form.table_no.data if form.order_type.data == 'dine-in' else None,
            quantity=form.quantity.data,
            amount=form.amount.data
        )
        db.session.add(bill)
        db.session.commit()
        flash('Bill has been added!', 'success')
        return redirect(url_for('billing'))
    return render_template('billing.html', title='Billing', form=form)

@app.route("/revenue")
@login_required
def revenue():
    bills = Bill.query.all()
    total_revenue = sum(bill.amount * bill.quantity for bill in bills)
    return render_template('revenue.html', title='Revenue', total_revenue=total_revenue, bills=bills)

@app.route("/branch/<int:branch_id>")
def branch(branch_id):
    branch = Branch.query.get_or_404(branch_id)
    return render_template('branch.html', title=branch.name, branch=branch)

@app.route("/add_branch", methods=['GET', 'POST'])
@login_required
def add_branch():
    form = BranchForm()
    if form.validate_on_submit():
        branch = Branch(
            name=form.name.data,
            address=form.address.data,
            pincode=form.pincode.data,
            contact_number=form.contact_number.data,
            contact_person=form.contact_person.data,
            description=form.description.data
        )
        db.session.add(branch)
        db.session.commit()
        flash('Branch has been added!', 'success')
        return redirect(url_for('home'))  # Redirect to home page after adding branch
    return render_template('add_branch.html', title='Add Branch', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
