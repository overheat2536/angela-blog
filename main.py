from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from functools import wraps
from flask import abort
import forms
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##Gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONFIGURE TABLES

class User(UserMixin,db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250),unique=True,nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), unique=False, nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments",back_populates="author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    post_comment = relationship("Comments", back_populates="post")


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer,primary_key=True)
    comment = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    post = relationship("BlogPost", back_populates="post_comment")
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="comments")
#
# with app.app_context():
#     db.create_all()
#     print('created')

## Create Form
class RegisterForm(FlaskForm):
    email = EmailField('Email',[DataRequired()])
    password = PasswordField('Password',[DataRequired()])
    name = StringField('Name', [DataRequired()])
    submit = SubmitField('Sign me up!')

class LoginForm(FlaskForm):
    email = EmailField('Email',[DataRequired()])
    password = PasswordField('Password',[DataRequired()])
    submit = SubmitField('Log me in!')


## Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        try:
            if current_user.id != 1:
                return abort(403)
        except:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    try:
        if current_user.id == 1:
            admin_account = True
        else:
            admin_account = False
    except:
        admin_account = False
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, admin=admin_account)

@app.route('/register',methods=["GET","POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("You have already signed up with that email, login instead!")
            return redirect(url_for('login'))
        else:
            hash_and_salted = generate_password_hash(form.password.data,'pbkdf2:sha256',salt_length=8)
            new_user = User(
                email = form.email.data,
                password = hash_and_salted,
                name = form.name.data
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))
    return render_template("register.html", form=form, logged_in=False)

@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        emailadd = form.email.data
        if User.query.filter_by(email=emailadd).first():
            user = User.query.filter_by(email=emailadd).first()
            if check_password_hash(user.password,form.password.data):
                login_user(user)
                # flash('Logged in successfully.')
                return redirect(url_for('get_all_posts', logged_in=True))
            else:
                flash('Wrong Password')
        else:
            flash('Email does not exist')
    return render_template("login.html", form=form, logged_in=False)


@app.route("/post/<int:post_id>",methods=["GET","POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comments = Comments.query.filter_by(post_id=post_id).all()
    comment_form = forms.CommentForm()
    if comment_form.validate_on_submit() and current_user.is_authenticated:
        new_comment = Comments(
            comment = comment_form.comment.data,
            post_id = post_id,
            author_id = current_user.id
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post',post_id=post_id))
    elif comment_form.validate_on_submit():
        flash("Please login to submit a comment")
        return redirect(url_for('login'))
    return render_template("post.html", post=requested_post,logged_in=current_user.is_authenticated, comment_form=comment_form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post",methods=["GET","POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts", logged_in=current_user.is_authenticated))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>",methods=["GET","POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        # author=post.author.name,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.name.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, logged_in=current_user.is_authenticated))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))

if __name__ == "__main__":
    app.run(debug=True)
