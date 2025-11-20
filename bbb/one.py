from flask import Flask,render_template,redirect,url_for,session,flash,request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,UserMixin,login_user,logout_user,current_user,login_required
from datetime import timedelta
from werkzeug.security import generate_password_hash,check_password_hash
import secrets
app = Flask(__name__)
app.permanent_session_lifetime = timedelta(seconds=15)
app.secret_key = secrets.token_urlsafe(64)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///kiama.db"
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'error'
class User(UserMixin,db.Model):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(120),unique=True,nullable=False)
    password = db.Column(db.String(120),nullable=False)


with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
@app.route('/')
def home():
    return render_template('signup.html')

@app.route('/signup',methods=["POST","GET"])
def signup():
    if request.method=="POST":
        username = request.form["username"].lower()
        password = request.form["password"].lower()
        confirm = request.form["confirm"].lower()
        if not username or not password:
            flash("Username or Password Must fill out","error")
            return redirect(url_for("login"))
        else:
            if len(password) >120 or len(username)>120:
                flash("Username or Password Must Contain Max 120 Characters","error")
                return redirect(url_for("login"))
            else:
                if len(password) <4:
                    flash("Password Must Contain at least 4 characters long","error")
                    return redirect(url_for("signup"))
                else:
                    exists_user = User.query.filter_by(username=username).first()
                    if exists_user:
                        flash("Username already exists","error")
                        return redirect(url_for("signup"))
                    else:
                        if password !=confirm:
                            flash("Password Doesn't Match","error")
                            return redirect(url_for("signup"))
                        else:
                            pass_hash = generate_password_hash(password)
                            user_data = User(username=username,password=pass_hash)
                            db.session.add(user_data)
                            db.session.commit()
                            session["username"]=username
                            flash("Registered Successfully","success")
                            return redirect(url_for("dashboard"))

    else:
        return render_template("signup.html")
                             
                            







@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html",username=current_user.username)


@app.route('/login',methods=["POST","GET"])

def login():
    if request.method=="POST":
        username = request.form["username"].lower()
        password = request.form["password"].lower()
        if not username or not password:
            flash("Username or Password Must fill out","error")
            return redirect(url_for("login"))
        else:
            if len(password) >120 or len(username)>120:
                flash("Username or Password Must Contain Max 120 Characters","error")
                return redirect(url_for("login"))
            else:
                if len(password) <4:
                    flash("Password Must Contain at least 4 characters long","error")
                    return redirect(url_for("login"))
                else:
                    exists_user = User.query.filter_by(username=username).first()
                    if exists_user:
                            flash("Login Successfully","success")
                            login_user(exists_user)
                            return redirect(url_for("dashboard"))


                    else:


                         flash("Username Doesn't Exists",'error')
                         return redirect(url_for("login"))

    else:
        return render_template("login.html")
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))
if __name__=="__main__":
    app.run(debug=True,port=7654)


