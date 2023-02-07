from enum import unique
from flask import Flask, render_template, redirect,flash,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField , SubmitField,BooleanField 
from wtforms.validators import Length,Email, DataRequired, EqualTo, ValidationError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin,login_user,login_required,logout_user 



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = '9fc11663bdbc82bbc552cc41'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return user.query.get(int(user_id))



## All models

@login_manager.user_loader
def load_user(user_id):
    return user.query.get(int(user_id))

class user(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(length=30), nullable=False,unique=True)
    email_address = db.Column(db.String(length=50), nullable=False,unique=True)
    password_hash = db.Column(db.String(length=60), nullable=False)
    budget = db.Column(db.Integer(),default=100)
    items= db.relationship('Item', backref='owned_user', lazy=True)

    
        
        
class Item(db.Model):
    
        
    
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(length=50), nullable=False,unique=True)
    price = db.Column(db.Integer(), nullable=False, unique=False)
    barcode= db.Column(db.String(length=12), nullable=False,unique=True)
    description = db.Column(db.String(length=100), nullable=True, unique=False)
    owner = db.Column(db.Integer(),db.ForeignKey('user.id'))

    def __repr__(self) -> str:
        return f'Item {self.name}'
    


     #Forms 
     
class RegisterForm(FlaskForm):
    
        def validate_username(self,user_to_check):
            name = user.query.filter_by(username = user_to_check.data).first()
            if name:
                raise ValidationError("User name already taken, please use a different name")
                    
            
        def validate_email_address(self,email_to_check):
            email= user.query.filter_by(email_address = email_to_check.data).first()
            if email:
                raise ValidationError("Email  already taken, please use a different email")
                    
            
        username = StringField(label="User Name:", validators=[Length(min=3, max=20),DataRequired()])
        email_address = StringField(label="Email Address:", validators=[Email(),DataRequired()])
        password1= PasswordField(label="Password:" ,validators=[Length(min=6),DataRequired()])
        password2 = PasswordField(label="Confirm Password", validators=[EqualTo('password1'), DataRequired()])
        submit= SubmitField(label="Create Account")
        
        
class LoginForm(FlaskForm):
    username = StringField(label="User Name:", validators=[DataRequired()])
    password = PasswordField(label="Password:" ,validators=[DataRequired()])
    submit = SubmitField(label="Login")
    
    
### all application routes
 
@app.route("/")
@app.route("/home")
def home_page():
    return render_template('home.html')


@app.route("/market")
def market_page():
    items = Item.query.all()
    return render_template('market.html' , items=items)


@app.route("/register", methods=['GET','POST'])
def register_page():
    form = RegisterForm()
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password1.data).decode('utf-8')
        new_user = user(username = form.username.data,
                        email_address= form.email_address.data,
                        password_hash= hashed_password) 
        db.session.add(new_user)
        db.session.commit()
        flash(f"Account created sucessfully, you are now logged in as: {user.username}",category="success")
        return redirect(url_for('login_page'))
    if form.errors !={}:
        for error_massege in form.errors.values():
            flash(f"Sorry there was an error in creating your account:{error_massege} ",category="danger")
    
    
    return render_template('register.html', form=form)

@app.route("/login", methods=['GET','POST'])
def login_page():
    form =LoginForm() 
    if form.validate_on_submit():
        attempted_user = user.query.filter_by(username = form.username.data).first()
        if  attempted_user and bcrypt.check_password_hash(user.password_hash, form.password.data):
                login_user(attempted_user)
                return redirect(url_for('market_page'))
                flash(f"you are now login as {user.username}", category='success')
                return redirect(url_for('market_page'))
        else:
            flash("Username and password not found", category='danger')
    
    return render_template('login.html', form=form)

with app.app_context():
    db.create_all()

if __name__ =='__main__':
    app.run(debug=True)