from flask import Flask, render_template,redirect,url_for,session,flash,request,send_from_directory,send_file
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,FileField
from wtforms.validators import  DataRequired, Email, ValidationError
import bcrypt
import mysql.connector
from mysql.connector import Error
import smtplib
from random import randint
import os
import io
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from email_validator import validate_email, EmailNotValidError

app=Flask(__name__)
app.secret_key="tauseef@123"

app.config['MAIL_SERVER']='smtp.gmail.com'  
app.config['MAIL_PORT']=587  
app.config['MAIL_USERNAME'] = 'rgmsotp@gmail.com'  
app.config['MAIL_PASSWORD'] = 'cajfytnczkdwbenn'  
app.config['MAIL_USE_TLS'] = True  
app.config['MAIL_USE_SSL'] = False    
mail = Mail(app)

UPLOAD_FOLDER = 'D:/Python programmings/flask_app/static/UPLOAD_FOLDER'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    print("heelo")

mycon=mysql.connector.connect(host="localhost",user ="root",passwd="root",database="students")
cursor=mycon.cursor()

class RegisterForm(FlaskForm):
	name = StringField("Name",validators=[DataRequired()])
	email= StringField("Email",validators=[DataRequired(),Email()])
	profile_image = FileField("Profile Image")
	password=PasswordField("password",validators=[DataRequired()])
	submit = SubmitField("Register")

	def validate_email(self,field):
		mycon=mysql.connector.connect(host="localhost",user ="root",passwd="root",database="students")
		cursor=mycon.cursor()
		sql="SELECT * FROM users"
		cursor.execute("SELECT * FROM users WHERE email=%s",(field.data,))
		user=cursor.fetchone()
		cursor.close()

		if user:
			raise ValidationError("Email Already taken")

class LoginForm(FlaskForm):
	email= StringField("Email",validators=[DataRequired(),Email()])
	password=PasswordField("password",validators=[DataRequired()])
	submit = SubmitField("Login")

class ForgotForm(FlaskForm):
	email= StringField("Email",validators=[DataRequired(),Email()])

@app.route('/')
def index():
    user_logged_in = 'user_id' in session
    user_image = session.get('user_image', '')  # Default to 'default.png' if no image
    name = session.get('user_name', '')
    
    return render_template(
        'index.html',
        user_logged_in=user_logged_in,
        user_image=user_image,
        name=name
    )

@app.route('/register',methods=['POST','GET'])
def register():
	filename={};
	mycon=mysql.connector.connect(host="localhost",user ="root",passwd="root",database="students")
	cursor=mycon.cursor()
	form=RegisterForm()
	if form.validate_on_submit():
		Uname=form.name.data
		Uemail=form.email.data
		Upassword=form.password.data
		profile_image = form.profile_image.data

		if profile_image and allowed_file(profile_image.filename):
			filename = secure_filename(profile_image.filename)
			filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
			profile_image.save(filepath)
		else:
			filename = None

		hashed_pass=bcrypt.hashpw(Upassword.encode('utf-8'),bcrypt.gensalt())

		sql="INSERT INTO users(name,email,password,p_image) VALUES (%s,%s,%s,%s)"
		val=(Uname,Uemail,hashed_pass,filename)
		cursor.execute(sql,val)
		mycon.commit();
		cursor.close();
		return redirect(url_for('login'))

	return render_template('register.html',form=form,image=filename)

@app.route('/login',methods=['GET','POST'])
def login():

	mycon=mysql.connector.connect(host="localhost",user ="root",passwd="root",database="students")
	cursor=mycon.cursor()
	form=LoginForm()
	if form.validate_on_submit():
		Uemail=form.email.data
		password=form.password.data

		sql="SELECT * FROM users WHERE email=%s"
		cursor.execute(sql,(Uemail,))
		user = cursor.fetchone()
		cursor.close();
		if user and bcrypt.checkpw(password.encode('utf-8'),user[3].encode('utf-8')):
			session['user_id']=user[0]
			filename = user[4]
			filename = user[4] if user[4] else ''  # Use 'default.png' if filename is None
			session['user_image'] = filename  # Store filename in session for later use
			session['user_name'] = user[1]  # Store user name in session
			return redirect(url_for('index'))
		else:
			flash('Login failed! Please check your email and password!')
			return redirect(url_for('login'))

	return render_template('login.html',form=form)
'''
@app.route('/dashboard')
def dashboard():
	if 'user_id' in session:
		user_id = session['user_id']

		mycon = mysql.connector.connect(host="localhost",user="root",passwd="root",database="students")
		cursor = mycon.cursor()
		cursor.execute("SELECT * FROM users WHERE  	Id=%s",(user_id,))
		user = cursor.fetchone()
		cursor.close()
		mycon.close()

		if user:
			return render_template('dashboard.html',user=user)

	return redirect(url_for('login'))
'''
@app.route('/logout')
def logout():
    # Remove user-specific data from the session
    session.pop('user_id', None)
    session.pop('user_name', None)  # Remove user name from session
    session.pop('user_image', None)  # Remove user image from session

    flash('You have been logged out successfully!')
    return redirect(url_for('index'))

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
	form=ForgotForm()
	if request.method == 'POST':
		email = request.form['Femail']

		conn = mysql.connector.connect(host="localhost",user ="root",passwd="root",database="students")
		cursor = conn.cursor()
		cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
		user = cursor.fetchone()
		if user:
			otp = randint(1000, 9999)
			session['otp'] = otp  # Store OTP in session
			session['email'] = email  # Store email in session
			try:
				msg=Message('Your One Time Password (OTP) for verification',
            		sender='rgmsotp@gmail.com',
            		recipients=[email])
				msg.body =f'OTP code is {otp}.'
				mail.send(msg)
				flash('OTP has been sent to your email!', 'success')
				cursor.close()
				conn.close()
				return redirect(url_for('verify_otp'))
			except Exception as e:
				flash(f'Failed to send email: {e}', 'danger')
				cursor.close()
				conn.close()
		else:
			flash('Email not found!', 'danger')
			cursor.close()
			conn.close()
	return render_template('forgot.html',form=form)

@app.route('/verify', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        actual_otp = session.get('otp')  # Retrieve OTP from session

        if entered_otp == str(actual_otp):  # Compare OTPs
            flash('OTP verified successfully!', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            return redirect(url_for('verify_otp'))

    return render_template('verify_otp.html')

@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = session.get('email')  # Retrieve email from session
        new_password = request.form['newPassword']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        # Connect to the database
        conn = mysql.connector.connect(host="localhost",user ="root",passwd="root",database="students")
        cursor = conn.cursor()

        # Update the password in the database
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
        conn.commit()

        cursor.close()
        conn.close()

        # Clear session data after password reset
        session.pop('otp', None)
        session.pop('email', None)

        flash('Your password has been reset successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

if __name__=="__main__":
	app.run(debug=True)