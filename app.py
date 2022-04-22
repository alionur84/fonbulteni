from flask import Flask, render_template, flash, request, redirect, url_for
from functools import wraps
import json

# fon and prices handler reqs
from name_handler import names_scrapper
from get_fx_prices import *
from anglifier import anglify

# form libs
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, SelectField, SelectMultipleField, RadioField, FieldList
from wtforms.validators import ValidationError, DataRequired, EqualTo, Length, Email
from wtforms_sqlalchemy.fields import QuerySelectField
from wtforms import widgets

# time libs
from datetime import datetime
import pytz


# password hash handling lib
from werkzeug.security import generate_password_hash, check_password_hash

# tokenizer
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

# database libs
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

#user login lib
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

# flask mailer
from flask_mail import Mail, Message

import os
import random
from sqlalchemy.sql.expression import func, select

app=Flask(__name__)

app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
database_pass = os.environ['JAWS_DB_PASS']

app.config['SQLALCHEMY_DATABASE_URI']= f'mysql+pymysql://fdey3jmsoxclbe65:{database_pass}@jtb9ia3h1pgevwb1.cbetxkdyhwsb.us-east-1.rds.amazonaws.com/ibqvixcsynsqkh9y'

# db instance
db = SQLAlchemy(app)

# migrate instance
migrate = Migrate(app, db)

# Flask mailer configs
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ['MAIL_USER']
app.config['MAIL_PASSWORD'] = os.environ['MAIL_PASS']
mail = Mail(app)


# Flask Login requirements
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Bu sayfayı görüntülemek için lütfen giriş yapınız"

# this will load user when we login
@login_manager.user_loader
def load_user(client_id):
	return Clients.query.get(int(client_id))


# investment fund db model
class InvestmentFund(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	fundname = db.Column(db.String(200), nullable=False)
	fundabbrv = db.Column(db.String(10), nullable=False, unique=True)
	portfolio = db.Column(db.String(30), nullable=False)
	date_added = db.Column(db.DateTime, default=datetime.utcnow())
	todays_price = db.Column(db.Float())
	date_of_price = db.Column(db.DateTime)
	daily_change = db.Column(db.String(30))
	first_price = db.Column(db.Float(), default=0)
	first_price_date = db.Column(db.DateTime)
	def __repr__(self):
		return '%r' % self.fundname

preferences = db.Table('preferences',
    db.Column('fund_id', db.Integer, db.ForeignKey('investment_fund.id'), primary_key=True),
    db.Column('client_id', db.Integer, db.ForeignKey('clients.id'), primary_key=True)
)

# this is user db model
# Usermixin that we pass to the class is required for login operations

class Clients(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), nullable=False, unique=True)
	name = db.Column(db.String(200), nullable=False)
	email = db.Column(db.String(120), nullable=False, unique=True)
	password_hash = db.Column(db.String(128))
	date_added = db.Column(db.DateTime, default=datetime.utcnow())
	preferences = db.relationship('InvestmentFund', secondary=preferences, lazy='dynamic',
        backref=db.backref('client', lazy=True))
	verified = db.Column(db.Boolean(), default=False)
	mail_pref = db.Column(db.Boolean(), default=True)

	def get_email_verify_token(self, expires_sec=1800):
		s = Serializer(app.config['SECRET_KEY'], expires_sec)
		return s.dumps({'user_id': self.id}).decode('utf-8')

	@staticmethod
	def verify_email_verify_token(token):
		s = Serializer(app.config['SECRET_KEY'])
		try:
			user_id = s.loads(token)['user_id']
		except:
			return None
		return Clients.query.get(user_id)


	# password properties
	@property
	def password(self):
		raise AttributeError('Password is not a readable attribute')

	# take the password entered and generate a password hash
	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	# check if password hash matches the password 
	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)


	def __repr__(self):
		return '<Name %r>' % self.name





# dictionary for lists used in choicebox & multiplechoice forms

def funds_dict_creator():
	portfolio_names = []
	for portfolio_name in InvestmentFund.query.distinct(InvestmentFund.portfolio):
	 	portfolio_names.append(portfolio_name.portfolio)
	portfolio_names = list(set(portfolio_names))
	portfolio_names.sort()
	
	funds_dict = {}

	for portfolio_name in portfolio_names:
	    data = InvestmentFund.query.filter_by(portfolio=f'{portfolio_name}').all()
	    fon_names = [item.fundname for item in data]
	    fon_codes = [item.fundabbrv for item in data]
	    codes_names = []
	    for count, fon_name in enumerate(fon_names):
	    	codes_names.append((fon_codes[count], fon_name))

	    funds_dict[f'{portfolio_name}'] = codes_names

	return funds_dict

funds_dict = funds_dict_creator()


# this is registration form 

class RegisterForm(FlaskForm):
	name = StringField("Ad", validators=[DataRequired()])
	username = StringField("Kullanıcı Adı", validators=[DataRequired()])
	email = StringField("Email", validators=[DataRequired(), Email(message='Lütfen Geçerli Bir Email Adresi Giriniz!!')])
	password = PasswordField("Parola", validators=[DataRequired(), EqualTo('password2', message='Parolalar Eşleşmiyor!!')])
	password2 = PasswordField("Parola Tekrar", validators=[DataRequired()])
	#old_password = PasswordField("Eski Parola", validators=[DataRequired()])
	submit = SubmitField('Kayıt Ol')
	update = SubmitField('Güncelle')

# this is login form

class LoginForm(FlaskForm):
	username = StringField("Kullanıcı Adı", validators=[DataRequired()])
	password = PasswordField("Parola", validators=[DataRequired()])
	submit = SubmitField('Giriş')

# multicheckbox for selecting multiple investment funds in user dashboard
class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()

# This is request email confirmation form

class VerifyForm(FlaskForm):
	email = StringField("Email", validators=[DataRequired(), Email(message='Lütfen Geçerli Bir Email Adresi Giriniz!!')])
	submit = SubmitField('Gönder')

# this is user preferences form

class ChoiceForm(FlaskForm):
	req_funds = SelectMultipleField('Fon Seçiniz') # fon name list
	radios = MultiCheckboxField() # user preferences list
	submit = SubmitField('Kaydet')
	submit2 = SubmitField('Seçilenleri Sil')

# this is search form

class SearchForm(FlaskForm):
	searched = StringField("Searched", validators=[DataRequired()])
	search = SubmitField('Ara')

# this is reset password form

class ResetPasswordForm(FlaskForm):
	new_password = PasswordField("Yeni Parola", validators=[DataRequired(), EqualTo('new_password2', message='Parolalar Eşleşmiyor!!')])
	new_password2 = PasswordField("Yeni Parola Tekrar", validators=[DataRequired()])
	submit = SubmitField('Kaydet')

# this is update password form

class UpdatePasswordForm(FlaskForm):
	old_password = PasswordField("Mevcut Parola", validators=[DataRequired()])
	new_password = PasswordField("Yeni Parola", validators=[DataRequired(), EqualTo('new_password2', message='Parolalar Eşleşmiyor!!')])
	new_password2 = PasswordField("Yeni Parola Tekrar", validators=[DataRequired()])
	submit = SubmitField('Kaydet')

# pass stuff to navbar
# use it for search purposes

@app.context_processor
def base():
	form = SearchForm()
	return dict(form=form)

# email confirm checker wrap

def check_confirmed(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.verified is False:
            flash('Lütfen Email Adresinizi Onaylayınız', 'warning')
            return redirect(url_for('request_verify'))
        return func(*args, **kwargs)

    return decorated_function

# main page

@app.route("/")
@app.route("/home")
def home():
	homepage = True
	if current_user.is_authenticated:
		try:
			funds_to_display = random.sample(current_user.preferences.all(), k=3)
		except:
			funds_to_display = random.sample(InvestmentFund.query.all(), k=3)
	else:
		funds_to_display = random.sample(InvestmentFund.query.all(), k=3)
	try:
		usd = round(float(get_usd_price()), 2)
		eur = round(float(get_eur_price()), 2)
		gbp = round(float(get_gbp_price()), 2)
	except:
		usd = round(float(get_alternative_usd_price()), 2)
		eur = round(float(get_alternative_eur_price()), 2)
		gbp = round(float(get_alternative_gbp_price()), 2)

	dt_now = datetime.utcnow()
	now = dt_now.strftime('%d'+'/'+'%-m'+'/'+'%Y')
	
	return render_template("index.html", homepage=homepage, usd=usd, gbp=gbp, eur=eur, now=now, funds_to_display=funds_to_display)


# portfolio page

@app.route("/portfolio", methods=['GET', 'POST'])
@login_required
@check_confirmed
def portfolio():
	# this page creates a dropdown based on portfolio names in funds_dict.keys()
	# the dropdown in user html dynamically creates links to /funds/<portfolio_name>
	dashboard = True
	portofolio_list = funds_dict.keys()
	all_funds = InvestmentFund.query.all()
	form = SearchForm()
	return render_template('portfolio.html', portofolio_list=portofolio_list, all_funds=all_funds, dashboard=dashboard, form=form, title='Portföy Seçiniz')

# funds page
# displays a multiple select field according to the fund picked in the portfolio page
 
@app.route("/funds/<portfolio_name>", methods=['GET', 'POST'])
@login_required
@check_confirmed
def funds(portfolio_name):
	form=ChoiceForm()
	dashboard = True
	client_to_update = Clients.query.get_or_404(current_user.id)
	form.req_funds.choices = funds_dict[portfolio_name]
	choice = ''
	if form.validate_on_submit():
		choice = form.req_funds.data
		data_to_post = []
		if client_to_update.preferences.count() + len(choice) > 10:
			flash('10 adetten fazla fon ekleyemezsiniz!!', 'warning')
			return redirect(url_for('dashboard'))
		else:
			for i in choice:
				fund = InvestmentFund.query.filter_by(fundabbrv=i).first()
				if fund in current_user.preferences: # checks if investment fund is already in user's list
					flash(f'{fund.fundname} - Fon Zaten Listenizde!!', 'warning')
					return redirect(url_for('portfolio'))
				else: # adds it if not
					client_to_update.preferences.append(fund) 
		try:
			db.session.commit()
			flash('Fonlar Listenize Eklendi!!', 'success')
			return redirect(url_for('dashboard'))
		except:
			flash('Error! Looks like there is an error in updating user info', 'danger')
			return render_template("funds.html",
				form=form,
				client_to_update=client_to_update)
	return render_template('funds.html', form=form, dashboard=dashboard, choice=choice, client_to_update=client_to_update, title='Fon Seçiniz')

# dashboard

@app.route("/dashboard", methods=['GET', 'POST'])
@login_required 
@check_confirmed
def dashboard():
	dashboard = True
	form = ChoiceForm()
	choice_list = []
	funds_to_delete=[]
	all_funds = []
	investment_summary = []

	# "yatirim gorunumu" section. calculates the price change against the first price of the investment fund in the database
	for i in current_user.preferences: 
		first_price = i.first_price
		first_price_date = i.first_price_date
		change = round((((i.todays_price - first_price)/first_price)*100), 4)
		investment_summary.append([i.fundabbrv, i.fundname, i.todays_price, i.daily_change, change, first_price_date.strftime('%d'+'/'+'%-m'+'/'+'%Y')])
		choice_list.append((i.fundabbrv,f'{i.fundname} - {i.fundabbrv}'))
	 	
	
	# puts a checkbox next to the user's funds. if checked, deletes the fund
	form.radios.choices = choice_list

	# first compares the user's fund list with the submitted form, deletes the funds from the list accordingly
	if form.validate_on_submit():
		for i in current_user.preferences:
			all_funds.append(i.fundabbrv)
		funds_to_delete = form.radios.data
		funds_to_remain = [item for item in all_funds if item not in funds_to_delete]
		update_record = []
		for i in funds_to_remain:
			fund = InvestmentFund.query.filter_by(fundabbrv=f'{i}').first()
			update_record.append(fund)

		current_user.preferences = update_record
		try:
			db.session.commit()
			flash('Fonlar Listenizden Silindi!', 'info')
			return redirect(url_for('dashboard'))
		except:
			flash('Error! Looks like there is an error in updating user preferences', 'danger')
			return render_template("dashboard.html", dashboard=dashboard, form=form, investment_summary=investment_summary, title='Kullanıcı Paneli')
	return render_template("dashboard.html", dashboard=dashboard, form=form, investment_summary=investment_summary, title='Kullanıcı Paneli')



# Search function

@app.route('/search', methods=["GET","POST"])
def search():
	form = SearchForm()
	funds = InvestmentFund.query
	if form.validate_on_submit():
		org_search = form.searched.data # includes turkish characters to display on html/original search
		searched = anglify(form.searched.data.upper()) # without turkish characters to query the database
		funds = funds.filter(InvestmentFund.fundname.like('%' + searched + '%')) #query db
		funds = funds.order_by(InvestmentFund.fundname).all()
		fund_code_search = InvestmentFund.query.filter_by(fundabbrv=searched).first()
		return render_template('search.html', form=form, searched=searched, org_search=org_search, funds=funds, fund_code_search=fund_code_search, title='Fon Ara')
	else:
		return render_template('index.html')

# adds funds from search list
# checks first if fund is already in the list

@app.route('/searchadd/<fund_code>', methods=['GET'])
@login_required
@check_confirmed
def search_add(fund_code):
	client_to_update = Clients.query.get_or_404(current_user.id)
	fund = InvestmentFund.query.filter_by(fundabbrv=fund_code).first()
	if fund in current_user.preferences:
		flash(f'{fund.fundname} - Fon Zaten Listenizde!!', 'warning')
		return redirect(url_for('dashboard'))
	elif client_to_update.preferences.count() >= 10:
		flash('10 adetten fazla fon ekleyemezsiniz!!', 'warning')
		return redirect(url_for('dashboard'))
	else:
		client_to_update.preferences.append(fund) 
	try:
		db.session.commit()
		flash('Fon Listenize Eklendi!!', 'success')
		return redirect(url_for('dashboard'))
	except:
		flash('Error! Looks like there is an error in updating user info', 'danger')


# User register

@app.route("/register", methods=['GET', 'POST'])
def register():
	register = True 
	name = None
	email = None
	username = None
	form = RegisterForm()
	if form.validate_on_submit():
		# check the database if the user exists
		email = Clients.query.filter_by(email=form.email.data).first()
		username = Clients.query.filter_by(username=form.username.data).first()
		if (email is None) and (username is None): #if user doesn't exist
			# hash the password
			hashed_password = generate_password_hash(form.password.data, "sha256")
			# create the client and commit to the db
			client = Clients(username=form.username.data, name=form.name.data, email=form.email.data, password_hash=hashed_password)
			db.session.add(client)
			db.session.commit()
			send_verify_email(client)
			flash("Kullanıcı Başarıyla Eklendi", 'success')
			return render_template('please_verify.html')
		else:
			flash("Var Olan Kullanıcı Adı/Email. Lütfen Tekrar Deneyiniz", 'danger')
			return redirect(url_for('register'))

	return render_template("register.html", register=register, form=form, title='Kayıt Ol')


# this function sends email confirmation mail with token
def send_verify_email(client):
	token = client.get_email_verify_token()
	msg = Message('Fon Bülteni - Hesabınızı Aktive Edin', sender='noreply@demo.com',
		recipients=[client.email])
	msg.body = f'''Hesabınızı aktive etmek için aşağıdaki linke tıklayınız.\n
{url_for('verify_email', token=token, _external=True)}\n
Eğer bu hesabı siz açmadıysanız bu emaili göz ardı edebilirsiniz.'''
	
	mail.send(msg)

# send password reset token

def reset_password_request(client):
	token = client.get_email_verify_token()
	msg = Message('Fon Bülteni - Parolanızı Sıfırlayın', sender='noreply@demo.com',
		recipients=[client.email])
	msg.body = f'''Parolanızı sıfırlamak için tıklayınız.\n
Kullanıcı adınız: {client.username}\n
Parola sıfırlama bağlantısı: {url_for('reset_password', token=token, _external=True)}\n
Eğer parola sıfırlama isteğini siz göndermediyseniz bu emaili göz ardı edebilirsiniz.'''
	
	mail.send(msg)


# user verify page with token

@app.route('/verify_email/<token>', methods=['GET', 'POST'])
def verify_email(token):
	client = Clients.verify_email_verify_token(token)
	if client is None:
		flash('Doğrulama linkinin süresi geçmiş, lütfen tekrar doğrulama emaili isteyiniz!', 'danger')
		return redirect(url_for('request_verify'))
	else:
		client.verified = True
	try:
		db.session.commit()
		flash('Emailinizi başarıyla doğruladınız!', 'success')
		return redirect(url_for('login'))
	except:
		flash('Error! Looks like there is an error in updating user info, please try again', 'danger')
		return redirect(url_for('request_verify'))


# if token expired or invalid user can request it again from this route
@app.route('/request_verify', methods=['GET', 'POST'])
def request_verify():
	form = VerifyForm()
	if request.method == "POST":
		email = request.form['email']
		client = Clients.query.filter_by(email=email).first()
		if client.verified == False:
			send_verify_email(client)
			flash('Doğrulama linki emailinize gönderildi! Lütfen kontrol ediniz', 'info')
			return redirect(url_for('home'))
		else:
			flash('Email zaten doğrulanmış!', 'warning')
			return redirect(url_for('home'))
	return render_template("request_verify.html", form=form, title='Doğrulama Emaili İste')

# request password reset

@app.route('/request_password_reset', methods=['GET','POST'])
def request_password_reset():
	form = VerifyForm()
	if request.method == "POST":
		email = request.form['email']
		client = Clients.query.filter_by(email=email).first()
		if client is not None: # if user exists
			reset_password_request(client)
			flash('Parolanızı sıfırlamak için talimatları içeren bir eposta girdiğiniz adrese gönderildi!', 'info')
		else: # if doesn't
			flash('Bu email sistemde kayıtlı değil, lütfen kayıt olunuz', 'danger')
			return redirect(url_for('register'))
	return render_template('request_password_reset.html', form=form, title='Parola Sıfırlama')

# reset password

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
	if current_user.is_authenticated:
		return redirect(url_for('dashboard'))	
	client = Clients.verify_email_verify_token(token)
	form = ResetPasswordForm()
	if client is None: # if token is expired or invalid
		flash('Parola sıfırlama linkinin süresi geçmiş, lütfen yeniden doğrulama linki isteyiniz', 'danger')
		return redirect(url_for('request_verify'))
	if form.validate_on_submit():
		password = form.new_password.data
		hashed_password = generate_password_hash(password, "sha256")
		client.password_hash = hashed_password
		db.session.commit()
		flash('Parolanız başarıyla güncellendi!', 'success')
		return redirect(url_for('login'))
	return render_template('reset_password.html', form=form, title='Parolayı Sıfırla')

# password update

@app.route('/password_update', methods = ['GET', 'POST'])
@login_required
@check_confirmed
def password_update():
	form = UpdatePasswordForm()
	if form.validate_on_submit():
		# first checks if the old password is correct
		if check_password_hash(current_user.password_hash, form.old_password.data):
			hashed_password = generate_password_hash(form.new_password.data, "sha256")
			current_user.password_hash = hashed_password
			db.session.commit()
			flash('Parolanız Başarıyla Güncellendi!', 'success')
			return redirect(url_for('dashboard'))

		else:
			flash('Eski Parola Hatalı!! Tekrar deneyiniz', 'danger')
			return redirect(url_for('password_update'))
	return render_template('password_update.html', form=form, title='Parolayı Güncelle')

# user update page
# workflow with if elses controls if data has changed or not, if email and username already exists or not
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
@check_confirmed
def update(id):
	form = RegisterForm()
	client_to_update = Clients.query.get_or_404(id)
	mail_updated = False
	if request.method == "POST":
		if request.form['username'] == '':
			client_to_update.username = client_to_update.username
		else:
			username = Clients.query.filter_by(username=request.form['username']).first()
			if username is None:
				client_to_update.username = request.form['username']
				flash('Kullanıcı adı güncellendi!', 'success')
			else:
				flash('Bu kullanıcı adı mevcut, lütfen tekrar deneyiniz!', 'danger')
		if request.form['name'] == '':
			client_to_update.name = client_to_update.name
		else:
			client_to_update.name = request.form['name']
			flash('İsim güncellendi!', 'success')
		if request.form['email'] == '':
			client_to_update.email = client_to_update.email 
		elif client_to_update.email != request.form['email']:
			email = Clients.query.filter_by(email=request.form['email']).first()
			if email is None:
				client_to_update.email = request.form['email']
				client_to_update.verified = False
				mail_updated = True
				flash('Emailinizi güncellediniz, lütfen hesabınızı tekrar aktive ediniz. Aktivasyon emaili verdiğiniz email adresine gönderildi!', 'info')
			else:
				flash('Bu email sistemde kayıtlı, lütfen başka email adresi ile deneyiniz!', 'danger')
		else:
			client_to_update.email = client_to_update.email

		try:
			db.session.commit()
			if mail_updated == True:
				send_verify_email(client_to_update)
			return render_template("user_update.html", form=form, client_to_update=client_to_update, title='Bilgileri Güncelle')
		except:
			flash('Error! Looks like there is an error in updating user info', 'danger')
			return render_template("user_update.html", form=form, client_to_update=client_to_update, title='Bilgileri Güncelle')

	else:
		return render_template("user_update.html",
				form=form, id = id, client_to_update=client_to_update, title='Bilgileri Güncelle')

# User login

@app.route("/login", methods=['GET', 'POST'])
def login():
	login = True
	form = LoginForm()
	
	if form.validate_on_submit():
		client = Clients.query.filter_by(username=form.username.data).first()
		if client:
			if check_password_hash(client.password_hash,form.password.data):
				login_user(client)
				flash("Giriş Başarılı!", 'success')
				# redirect successfull logins to dashboard
				return redirect(url_for("dashboard"))
			else: # username correct, password is wrong
				flash("Parola Hatalı! Tekrar Deneyin", 'danger')
		else: # username is incorrect
			flash('Bu Kullanıcı Kayıtlı Değil! Tekrar Deneyin', 'danger')
	
	return render_template("login.html", login=login, form=form, title='Giriş Yap')

# user logout

@app.route('/logout', methods = ['GET', 'POST'])
@login_required
def logout():
	logout_user() #this handles it
	flash('Çıkış Yaptınız!!', 'info')
	return redirect(url_for('home'))

# Delete User

@app.route('/delete/<int:id>')
def delete(id):
	# query the database by id. get the record 
	# assign it to user_to_delete variable if exists
	# if not return database error
	user_to_delete = Clients.query.get_or_404(id)
	name = None
	try:
	# delete the user from database. 
		db.session.delete(user_to_delete)
		db.session.commit()
		flash("Hesabınız Başarıyla Silindi!!", 'info')
	# return the add user page 
		return redirect(url_for('register'))
	except:
		flash("There was an error in deleting user, try again", 'danger')
		return redirect(url_for('register'))


# integrate a simple api for mailing purposes
# get method allows access point to send user preferences info
# put method allows access point to receive daily prices of funds
# for keys of the received data check price_putter.py or mailer_bones.py
@app.route('/jsoner', methods=['GET', 'PUT'])
def jsoner():
	username = request.authorization.username
	password = request.authorization.password
	if request.method == 'GET':
		if username == 'mailer' and password == os.environ['REQ_PASS']:
			data = {}
			our_clients = Clients.query.order_by(Clients.date_added)
			for client in our_clients:
				if (client.verified != False) & (client.mail_pref != False):
					data[client.email] = []
					for fund in client.preferences:
						data[client.email].append(fund.fundabbrv)
				else:
					continue
			return data
		else:
			return {'operation':'not allowed'}
	if request.method == 'PUT':
		if username == 'mailer' and password == os.environ['REQ_PASS']:
			new_data = request.get_json()
			for key in new_data.keys():
				fund = InvestmentFund.query.filter_by(fundabbrv=key).first()
				price = new_data[key][0].replace(',','.') # 0 price
				if fund:
					fund.todays_price = float(price)
					fund.daily_change = new_data[key][1] # 1 change in the received json
					fund.date_of_price = datetime.utcnow()
					if fund.first_price == 0:
						fund.first_price = float(price)
						fund.first_price_date = datetime.utcnow()
					else:
						continue
				else:
					continue

			try:
				db.session.commit()
				return {"operation" : "success"}
			except:
				return {"operation" : "faliure"}

#invalid url
@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html"), 404

#internal server error
@app.errorhandler(500)
def page_not_found(e):
	return render_template("500.html"), 500


if __name__ == '__main__':
	app.run(debug=False)