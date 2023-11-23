from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap4
from flask_sqlalchemy import SQLAlchemy
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
from datetime import date
import smtplib
import os
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ContactForm

EMAIL = os.environ["EMAIL"]
PASSWORD = os.environ["PASSWORD"]
SECRET_KEY = os.environ["SECRET_KEY"]

app = Flask(__name__)
app.secret_key = SECRET_KEY
bootstrap = Bootstrap4(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blog.db"
db = SQLAlchemy()
db.init_app(app)

ckeditor = CKEditor()
ckeditor.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False,
                    force_lower=False, use_ssl=False, base_url=None)

# DB TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    blog_posts = relationship("BlogPost", backref="blogger")
    comments = relationship("Comment", backref="writer")
    # blog_posts = relationship("BlogPost", back_populates="blogger")
    # comments = relationship("Comment", back_populates="writer")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    blogger_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # blogger = relationship("User", back_populates="blog_posts")
    comments = relationship("Comment", backref="post")
    # comments = relationship("Comment", back_populates="post")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    deleted = db.Column(db.Boolean, default=False, nullable=True)

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    writer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # writer = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    # post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)
    deleted = db.Column(db.Boolean, default=False, nullable=True)

# with app.app_context():
#     db.create_all()

# ADMIN ONLY DECORATOR
def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return function(*args, **kwargs)
    return wrapper

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

@app.route("/")
def get_all_posts():
    posts = db.session.execute(db.select(BlogPost).order_by(BlogPost.id)).scalars()
    return render_template("index.html", all_posts=posts)

@app.route("/register", methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        email = register_form.email.data
        password = register_form.password.data
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if user:
            flash("Email address already registered. Please log in.")
            return redirect(url_for("login"))
        hash_password = generate_password_hash(password, "pbkdf2", 12)
        new_user = User(
            name=register_form.name.data,
            email=email,
            password=hash_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=register_form)

@app.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if not user:
            flash("Unknown user. Please try again.")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, password):
            flash("Password incorrect. Please try again.")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=login_form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route("/post", methods=["GET", "POST"])
def show_post():
    post_id = request.args.get("post_id")  # alternative for using meaningful url
    comment_form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    if comment_form.validate_on_submit():
        new_comment = Comment(
            text=comment_form.comment_text.data,
            writer=current_user,
            post=requested_post,
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", post=requested_post, form=comment_form)

@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    post_form = CreatePostForm()
    if post_form.validate_on_submit():
        new_post = BlogPost(
            title=post_form.title.data,
            subtitle=post_form.subtitle.data,
            date=date.today().strftime("%B %d, %Y"),
            body=post_form.body.data,
            blogger=current_user,
            img_url=post_form.img_url.data,
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=post_form)

@app.route("/edit-post", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post():
    post_id = request.args.get("post_id")  # alternative for using meaningful url
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(obj=post)
    if edit_form.validate_on_submit():
        # edit_form.populate_obj(post)
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.body = edit_form.body.data
        post.img_url = edit_form.img_url.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)

@app.route("/delete")
@login_required
@admin_only
def delete_post():
    post_id = request.args.get("post_id")  # alternative for using meaningful url
    post_to_delete = db.get_or_404(BlogPost, post_id)
    post_to_delete.deleted = True
    # db.session.delete(post_to_delete)
    db.session.commit()
    for comment in post_to_delete.comments:
        comment.deleted = True
        db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/delete-comment/<int:comment_id>")
@login_required
def delete_comment(comment_id):
    # comment_id = request.args.get("comment_id") alternative for using meaningful url
    comment_to_delete = db.get_or_404(Comment, comment_id)
    post_id = comment_to_delete.post.id
    comment_to_delete.deleted = True
    # db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for("show_post", post_id=post_id))

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    contact_form = ContactForm()
    if contact_form.validate_on_submit():
        data = contact_form.data
        message = f"Name: {current_user.name}\nEmail: {data['email']}\nMessage:\n{data['message']}"
        with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(EMAIL, PASSWORD)
            connection.sendmail(EMAIL, EMAIL, msg=f"Subject: Blog User New Message\n\n{message}")
        return render_template("contact.html", msg_sent=True)
    return render_template("contact.html", form=contact_form, msg_sent=False)


if __name__ == "__main__":
    app.run(debug=True)
