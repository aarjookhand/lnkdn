from flask import *
import sqlite3
from pymongo import MongoClient
from flask_sqlalchemy import SQLAlchemy
from gridfs import GridFS
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from bson import ObjectId
from flask_caching import Cache 
from bson import Decimal128
from decimal import Decimal
from bson.decimal128 import Decimal128
from flask_login import current_user
from werkzeug.utils import secure_filename
from functools import wraps
from flask import flash, redirect, url_for



import os

if not os.path.exists('uploads'):
    os.makedirs('uploads')





app = Flask(__name__)
app.secret_key = 'your_secret_key'




client = MongoClient("mongodb://localhost:27017")
db = client['lnkdn']
collection = db['jobs']
applicant_collection = db['applicants']
users_collection = db['users']
ALLOWED_EXTENSIONS = {'pdf'}






fs = GridFS(db)

try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

conn = sqlite3.connect('lnkdn.db')
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS users
                  (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL,
                  email TEXT NOT NULL,
                  password TEXT NOT NULL,
                  is_admin INTEGER DEFAULT 0)''')

conn.commit()
conn.close()



login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)



class User(UserMixin):
    def __init__(self, id,  username, email, password, is_admin=False):
         self.id = id
         self.username = username
         self.email = email
         self.password = password
         self.is_admin = is_admin
         
         
    def is_active(self):
         return self.authenticated
    def is_anonymous(self):
         return False
    def is_authenticated(self):
         return self.authenticated

    def get_id(self):
         return str(self.email)


@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('lnkdn.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()

    if user_data:
        user = User(user_data[0], user_data[1], user_data[2], user_data[3])
        return user

    return None



class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log in')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, field):
        conn = sqlite3.connect('lnkdn.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (field.data,))
        existing_user = cursor.fetchone()
        conn.close()

        if existing_user:
            raise ValidationError('username alr taken')


    def validate_email(self, field):
        conn = sqlite3.connect('lnkdn.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (field.data,))
        existing_user = cursor.fetchone()
        conn.close()

        if existing_user:
            raise ValidationError('email alr taken')
        



conn_sqlite = sqlite3.connect('lnkdn.db')
cursor = conn_sqlite.cursor()
cursor.execute("SELECT * FROM users WHERE username = 'admin'")
admin_user_sqlite = cursor.fetchone()
conn_sqlite.close()





@app.route('/', methods=['GET'])
def display_welcome():
    return render_template('welcome.html')



def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = users_collection.find_one({"email": current_user.get_id()})
        if user and user.get("is_admin", False):
            return f(*args, **kwargs)
        else:
            flash("You don't have permission to access this page.")
            return redirect(url_for('home'))
    return decorated_function


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
   
        conn = sqlite3.connect('lnkdn.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
        else:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
            conn.commit()

            user_doc = {
                '_id': str(email), 
         
            }
            db.users.insert_one(user_doc)

            conn.close()

            flash("Successfully registered. You can now log in.")
            return redirect(url_for('login'))

    return render_template('register.html', form=form)




@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.is_submitted():
        print('form validated')
        username = form.username.data
        password = form.password.data

        conn = sqlite3.connect('lnkdn.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            user = User(user_data[0], user_data[1], user_data[2], user_data[3])
            login_user(user)
            current_user.email = user_data[2] 
            flash("Successfully logged in")
            print("Login email:", current_user.email)

            return redirect(url_for('home'))
    
        else:
            flash('Login Failed. Invalid Credentials')

    return render_template('login.html', form=form)


@app.route('/home')
@login_required
def home():
    return render_template('home.html')


@app.route('/post_jobs', methods=['GET', 'POST'])
@admin_required
def post_jobs():
    if request.method == 'POST':
        job_title = request.form.get('job_title')
        job_description = request.form.get('job_description')
        job_type = request.form.get('job_type')
        company_name = request.form.get('company_name')
        location = request.form.get('location')

        jobs = {
            "job_title": job_title,
            "job_description": job_description,
            "job_type" : job_type,
            "company_name" : company_name,
            "location" : location
        }
        collection.insert_one(jobs)
        flash('Job posted successfully')
    
    return render_template('post_jobs.html')




@app.route('/job_list', methods=['GET'])
def job_list():
    jobs = collection.find()    
    return render_template('job_list.html',jobs=jobs)


@app.route('/search_jobs', methods=['GET'])
def search_jobs():
    search_query = request.args.get('search_query')

    filtered_jobs = collection.find({
        '$or': [
            {'job_title': {'$regex': search_query, '$options': 'i'}},
            {'company_name': {'$regex': search_query, '$options': 'i'}},
            {'location': {'$regex': search_query, '$options': 'i'}}
        ]
    })

    return render_template('filtered_jobs.html', jobs=filtered_jobs)



@app.route('/job_details/<string:job_id>')
def job_details(job_id):
    print(f"job_id: {job_id}")
    job = collection.find_one({"_id": ObjectId(job_id)})

    if job:
        
        print(f"Job details found: {job}")
        return render_template('job_details.html', job=job)
    else:
        print("no job found for the particular id", job_id)
        abort(404)


  

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/apply/<job_id>', methods=['GET', 'POST'])
def apply(job_id):
    if request.method == 'POST':
        cv = request.files['cv']
        applicant_email = request.form.get('applicant_email')
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')


        if cv and allowed_file(cv.filename):
            cv_id = fs.put(cv, filename=cv.filename, content_type=cv.content_type)
            filename = secure_filename(cv.filename)
            
            

            application_data = {
                'user_id': current_user.get_id(),
                'job_id': job_id,
                'firstname' : firstname,
                'lastname' : lastname,
                'applicant_email': applicant_email,
                'cv_filename': filename,
                'cv_id' : cv_id
            }

            applicant_collection.insert_one(application_data)

            flash('Application submitted successfully')
            return redirect(url_for('job_details', job_id=job_id))

    return render_template('apply_form.html', job_id=job_id)


@app.route('/logout', methods=['GET'])
def logout():
    # Clear the user session to log the user out
    session.pop('user_id', None)
    return redirect(url_for('display_welcome'))



if __name__ == '__main__':
    app.run(debug=True)
