from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, RecaptchaField
from werkzeug.exceptions import default_exceptions
from wtforms import StringField, SubmitField, TextAreaField, PasswordField, BooleanField
from flask_wtf.file import FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_mail import Message, Mail
from flask_ckeditor import CKEditor, CKEditorField
from better_profanity import profanity
import requests
import html2text
import re
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
import humanize
import imghdr
import os
from werkzeug.utils import secure_filename
import pathlib
import base64
import random
import string
from ast import literal_eval as le
from uuid import uuid4 as uuid
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('PASS_SALT')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LfG-dEaAAAAAACcbNzZmr_E50lcKdJIwAIVQUCV'
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE')
app.config['MAIL_SERVER'] = "smtp.sendgrid.com"
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'apikey'
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASS')
app.config['UPLOAD_PATH'] = 'files'
ckeditor = CKEditor()
mail = Mail()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_message_category = 'info'
bcrypt.init_app(app)
login_manager.init_app(app)
ckeditor.init_app(app)
mail.init_app(app)
migrate = Migrate(app, db, render_as_batch=True)


def no_dispose(form, field):
    if requests.get(f'https://disposable.debounce.io/?email={field.data}').json()['disposable'] == 'true':
        raise ValidationError('Disposable Emails are not allowed')


def no_profane(form, field):
    if profanity.contains_profanity(html2text.html2text(field.data)):
        raise ValidationError('We strictly prohibit profane messages')


class Content(db.Model):
    date = db.Column(db.DateTime, nullable=False,
                     default=datetime.utcnow, primary_key=True)
    about = db.Column(db.Text(), nullable=False)
    skillonetitle = db.Column(db.Text(), nullable=False)
    skillonelevel = db.Column(db.Text(), nullable=False)
    skillone = db.Column(db.Text(), nullable=False)
    skilltwotitle = db.Column(db.Text(), nullable=False)
    skilltwolevel = db.Column(db.Text(), nullable=False)
    skilltwo = db.Column(db.Text(), nullable=False)
    skillthreetitle = db.Column(db.Text(), nullable=False)
    skillthreelevel = db.Column(db.Text(), nullable=False)
    skillthree = db.Column(db.Text(), nullable=False)
    skillfourtitle = db.Column(db.Text(), nullable=False)
    skillfourlevel = db.Column(db.Text(), nullable=False)

    def __repr__(self):
        return f"Content('{self.about}, {self.skillonetitle}, {self.skillonelevel}, {self.skillone}, {self.skilltwotitle}, {self.skilltwolevel}, {self.skilltwo}, {self.skillthreetitle}, {self.skillthreelevel}, {self.skillthree}, {self.skillfourtitle}, {self.skillfourlevel}')"


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.username}')"


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False,
                     default=datetime.utcnow)
    title = db.Column(db.String(100), nullable=False)
    thumbnail = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.Text, nullable=False)
    website_url = db.Column(db.Text, nullable=True)
    github_url = db.Column(db.Text, nullable=True)
    content = db.Column(db.Text, nullable=True)
    python = db.Column(db.Boolean, nullable=False)
    flask = db.Column(db.Boolean, nullable=False)
    django = db.Column(db.Boolean, nullable=False)
    htmlcss = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return f"User('{self.title}', '{self.image_url}', '{self.content}')"


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    path = db.Column(db.Text, nullable=False)
    fullpath = db.Column(db.Text, nullable=False)
    size = db.Column(db.Text, nullable=False)
    protected = db.Column(db.Boolean, nullable=False)
    password = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"File('{self.name}', '{self.path}', '{self.size}', '{self.protected}')"

class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.Text, nullable=False)
    options = db.Column(db.Text, nullable=False)
    votes = db.Column(db.Text, nullable=False)
    unique_id = db.Column(db.Text, nullable=False)
    multiplesubs = db.Column(db.Boolean, nullable=False)

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[
                       DataRequired(), Length(min=2, max=50)], render_kw={'placeholder': 'Example: John Doe', 'data-aos': 'zoom-in'})
    email = StringField('Email', validators=[DataRequired(), Email(), no_dispose], render_kw={
                        'placeholder': 'Example: johndoe@company.com', 'data-aos': 'zoom-in'})
    content = CKEditorField('Your Message', validators=[
                            DataRequired(), no_profane])
    recaptcha = RecaptchaField()
    submit = SubmitField('Message', render_kw={
                         'data-tilt': None, 'data-tilt-scale': '1.1'})


class VerifyForm(FlaskForm):
    submit = SubmitField('Send Verification Email')


class EditAboutForm(FlaskForm):
    about = CKEditorField('About Text')
    submit = SubmitField('Update')


class EditSkillsForm(FlaskForm):
    skillonetitle = StringField('Skill One Title')
    skillonelevel = StringField('Skill One Level(0-100)')
    skillone = CKEditorField('Skill One Description')
    skilltwotitle = StringField('Skill Two Title')
    skilltwolevel = StringField('Skill Two Level(0-100)')
    skilltwo = CKEditorField('Skill Two Description')
    skillthreetitle = StringField('Skill Three Title')
    skillthreelevel = StringField('Skill Three Level(0-100)')
    skillthree = CKEditorField('Skill Three Description')
    skillfourtitle = StringField('Skill Four Title')
    skillfourlevel = StringField('Skill Four Level(0-100)')
    submit = SubmitField('Update')


class ProjectForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    thumbnail = StringField('Thumbnail')
    image_url = StringField('Image URL')
    website_url = StringField('Website URL')
    github_url = StringField('GitHub URL')
    content = CKEditorField('Content')
    python = BooleanField('Uses Python')
    flask = BooleanField('Uses Flask')
    django = BooleanField('Uses Django')
    htmlcss = BooleanField('Uses HTML + CSS')
    submit = SubmitField('Add/Update')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=8, max=30)])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class UploadForm(FlaskForm):
    file = FileField()
    location = StringField(
        'Location of file (With slashes(E.g. coolfiles/latest/))')
    submit = SubmitField('Upload')


class PasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Access File')

class PollForm(FlaskForm):
    question = StringField('Question/Title', validators=[DataRequired()])
    options = TextAreaField('Options(Seperate by ||)',
                            validators=[DataRequired()])
    multiplesubs = BooleanField('Allow multiple submissions by one browser')
    recaptcha = RecaptchaField()
    submit = SubmitField('Create Poll')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=["GET", "POST"])
def home():
    words = ["Full-Stack Developer", "Pythonista", "Car Enthusiast",
             "Nutrition Geek", "Rubiks Cube Solver"]
    content = Content.query.order_by(Content.date.desc()).first()
    projects = Project.query.order_by(Project.date.desc())
    form = ContactForm()
    if form.validate_on_submit():
        tlen = len(form.name.data) + len(form.email.data) + 3
        msg = Message(f'New Message from {form.name.data} - {form.email.data}', sender=(
            form.name.data, 'noreply@eshan.dev'), recipients=['eshan.nalajala@gmail.com'])
        msg.html = f'<h4>{form.name.data} - {form.email.data}<br>{"=" * tlen}<br></h4>' + \
            form.content.data
        mail.send(msg)
        flash('Message Sent!', 'success')
        return redirect(f'{url_for("home")}#contact')
    return render_template("home.html", form=form, words=words, content=content, projects=projects, hurl=request.host_url)

@app.route('/poll', methods=['GET', 'POST'])
def poll_home():
    form = PollForm()
    if form.validate_on_submit():
        li = []
        for _ in range(len(form.options.data.split('||'))):
            li.append(0)
        uid = str(uuid())
        while(bool(Poll.query.filter_by(unique_id=uid).first())):
            uid = str(uuid())
        poll = Poll(question=form.question.data,
                    options=form.options.data, multiplesubs=form.multiplesubs.data, votes=str(li), unique_id=uid)
        db.session.add(poll)
        db.session.commit()
        flash(
            f'Your poll has been created! It can be accessed at: <a href="{request.host_url}poll/{poll.id}" target="_blank">{request.host_url}poll/{poll.id}</a>', 'success')
    return render_template('poll_home.html', form=form)


@app.route('/poll/<int:id>')
def poll(id):
    poll = Poll.query.filter_by(id=id).first_or_404()
    return render_template('poll.html', poll=poll, le=le, id=id)


@app.route('/poll/<id>/vote', methods=['POST'])
def vote(id):
    poll = Poll.query.filter_by(id=id).first_or_404()
    if session.get(f'voted:{poll.unique_id}') and poll.multiplesubs == False:
        flash('You have already voted', 'warning')
    else:
        options = poll.options.split('||')
        vote = request.form.get('vote')
        votes = le(poll.votes)
        votes[options.index(vote)] += 1
        poll.votes = str(votes)
        db.session.add(poll)
        db.session.commit()
        if not poll.multiplesubs:
            session[f'voted:{poll.unique_id}'] = True
            session.permanent = True
        flash('You have successfully voted!', 'success')
    return redirect(url_for('poll', id=id))


@app.route('/poll/manage')
@login_required
def manage_polls():
    if current_user.username != 'Eshan':
        abort(403)
    polls = Poll.query.all()
    return render_template('manage.html', polls=polls, le=le)


@app.route("/poll/<id>/delete", methods=['POST', 'GET'])
@login_required
def delete_poll(id):
    poll = Poll.query.get_or_404(id)
    if current_user.username != 'Eshan':
        abort(403)
    db.session.delete(poll)
    db.session.commit()
    flash('Your poll has been deleted!', 'success')
    return redirect(url_for('manage_polls'))


@app.route('/files')
@login_required
def files():
    if current_user.username != 'Eshan':
        abort(403)
    if current_user.is_authenticated:
        files = File.query.all()
    else:
        files = None
    return render_template('files.html', files=files, humanize=humanize)


def boolfc(fobject):
    if fobject == 'on':
        toret = True
    elif fobject == None:
        toret = False
    return toret


@app.route('/files', methods=['POST'])
@login_required
def upload_files():
    if current_user.username != 'Eshan':
        abort(403)
    files = request.files.getlist('file')
    location = request.form.get('location')
    protected = request.form.get('protected')
    password = request.form.get('password')
    if password == '' or boolfc(protected) == False:
        fpass = None
    else:
        hashed_password = bcrypt.generate_password_hash(
            password).decode("utf-8")
        fpass = hashed_password
    print(location)
    if location == None:
        location = ''
    for uploaded_file in files:
        filename = secure_filename(uploaded_file.filename)
        if File.query.filter_by(path=location+filename).first() != None:
            filename = base64.b64encode(os.urandom(6)).decode('ascii') + filename
        if filename != '':
            finalpath = os.path.join(
                app.config['UPLOAD_PATH'], location, filename)
            if not os.path.exists(os.path.dirname(finalpath)):
                os.makedirs(os.path.dirname(finalpath))
            uploaded_file.save(finalpath)
            newfile = File(name=filename, path=location + filename, fullpath=finalpath,
                        size=os.path.getsize(finalpath), protected=boolfc(protected), password=fpass)
            db.session.add(newfile)
            db.session.commit()
    return redirect(url_for('files'))


@app.route('/files/<path:filename>', methods=["GET", "POST"])
def getfiles(filename):
    file = File.query.filter_by(path=filename).first_or_404()
    if file.protected:
        if not current_user.is_authenticated:
            if file.password:
                if file.path in session:
                    return send_from_directory(app.config['UPLOAD_PATH'], file.path, as_attachment=True if request.args.get("dl") else False)
                password = request.form.get('password')
                if password:
                    if bcrypt.check_password_hash(file.password, password):
                        session[file.path] = True
                        return send_from_directory(app.config['UPLOAD_PATH'], file.path, as_attachment=True if request.args.get("dl") else False)
                    else:
                        flash(
                            'Password validation unsuccessful. Please try again', 'danger')
                return render_template('password.html', filename=filename, view='getfiles')
            else:
                abort(403)
        else:
            return send_from_directory(app.config['UPLOAD_PATH'], file.path, as_attachment=True if request.args.get("dl") else False)
    else:
        return send_from_directory(app.config['UPLOAD_PATH'], file.path, as_attachment=True if request.args.get("dl") else False)

@app.route('/files/<path:filename>/listdir')
def viewdir(filename):
    path = os.getcwd() + '/' + app.config['UPLOAD_PATH'] + '/' + filename + '/'

    if not os.path.exists(path):
        return abort(404)

    files = os.listdir(path)
    return render_template('viewdir.html', files=files, dr=filename, isdir=os.path.isdir, path=path)

@app.route('/files/<path:filename>/details', methods=["GET", "POST"])
def viewfile(filename):
    file = File.query.filter_by(path=filename).first_or_404()
    if file.protected:
        if not current_user.is_authenticated:
            if file.password:
                if file.path in session:
                    return render_template('view.html', file=file, humanize=humanize)
                password = request.form.get('password')
                if password:
                    if bcrypt.check_password_hash(file.password, password):
                        session[file.path] = True
                        return render_template('view.html', file=file, humanize=humanize)
                    else:
                        flash(
                            'Password validation unsuccessful. Please try again', 'danger')
                return render_template('password.html', filename=filename, view='viewfile')
            else:
                abort(403)
        else:
            return render_template('view.html', file=file, humanize=humanize)
    else:
        return render_template('view.html', file=file, humanize=humanize)


@app.route('/files/<path:filename>/delete', methods=["GET", "POST"])
def delete_file(filename):
    file = File.query.filter_by(path=filename).first_or_404()
    if file.protected:
        if not current_user.is_authenticated:
            if file.password:
                password = request.form.get('password')
                if password:
                    if bcrypt.check_password_hash(file.password, password):
                        os.remove(app.root_path + '/' + file.fullpath)
                        db.session.delete(file)
                        db.session.commit()
                        flash('File Deleted', 'success')
                        return redirect(url_for('files'))
                    else:
                        flash(
                            'Password validation unsuccessful. Please try again', 'danger')
                return render_template('password.html', filename=filename)
            else:
                abort(403)
        else:
            os.remove(app.root_path + '/' + file.fullpath)
            db.session.delete(file)
            db.session.commit()
            flash('File Deleted', 'success')
            return redirect(url_for('files'))
    elif current_user.is_authenticated:
        os.remove(app.root_path + '/' + file.fullpath)
        db.session.delete(file)
        db.session.commit()
        flash('File Deleted', 'success')
        return redirect(url_for('files'))
    else:
        abort(403)

'''@app.route('/files/<path:filename')'''

@app.route('/edit/about', methods=["GET", "POST"])
@login_required
def edit_about():
    if current_user.username != 'Eshan':
        abort(403)
    form = EditAboutForm()
    if form.validate_on_submit():
        toedit = Content.query.order_by(Content.date.desc()).first()
        toedit.about = form.about.data
        db.session.commit()
    elif request.method == "GET":
        form.about.data = Content.query.order_by(
            Content.date.desc())[0].about
    return render_template('edit_about.html', form=form)


@app.route('/edit/skills', methods=["GET", "POST"])
@login_required
def edit_skills():
    if current_user.username != 'Eshan':
        abort(403)
    form = EditSkillsForm()
    if form.validate_on_submit():
        toedit = Content.query.order_by(Content.date.desc()).first()
        toedit.skillonetitle = form.skillonetitle.data
        toedit.skillonelevel = form.skillonelevel.data
        toedit.skillone = form.skillone.data
        toedit.skilltwotitle = form.skilltwotitle.data
        toedit.skilltwolevel = form.skilltwolevel.data
        toedit.skilltwo = form.skilltwo.data
        toedit.skillthreetitle = form.skillthreetitle.data
        toedit.skillthreelevel = form.skillthreelevel.data
        toedit.skillthree = form.skillthree.data
        toedit.skillfourtitle = form.skillfourtitle.data
        toedit.skillfourlevel = form.skillfourlevel.data
        db.session.commit()
    elif request.method == "GET":
        toget = Content.query.order_by(Content.date.desc()).first()
        form.skillonetitle.data = toget.skillonetitle
        form.skillonelevel.data = toget.skillonelevel
        form.skillone.data = toget.skillone
        form.skilltwotitle.data = toget.skilltwotitle
        form.skilltwolevel.data = toget.skilltwolevel
        form.skilltwo.data = toget.skilltwo
        form.skillthreetitle.data = toget.skillthreetitle
        form.skillthreelevel.data = toget.skillthreelevel
        form.skillthree.data = toget.skillthree
        form.skillfourtitle.data = toget.skillfourtitle
        form.skillfourlevel.data = toget.skillfourlevel

    return render_template('edit_skills.html', form=form)


@app.route("/project/new", methods=['GET', 'POST'])
@login_required
def new_project():
    if current_user.username != 'Eshan':
        abort(403)
    form = ProjectForm()
    if form.validate_on_submit():
        project = Project(title=form.title.data, thumbnail=form.thumbnail.data, image_url=form.image_url.data,
                          website_url=form.website_url.data, github_url=form.github_url.data, content=form.content.data, python=form.python.data, flask=form.flask.data, django=form.django.data, htmlcss=form.htmlcss.data)
        db.session.add(project)
        db.session.commit()
        flash('Your project has been published!', 'success')
        return redirect(url_for('home'))
    return render_template('project.html', form=form, legend='New Project')


@app.route("/project/<project_id>/update", methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    if current_user.username != 'Eshan':
        abort(403)
    form = ProjectForm()
    if form.validate_on_submit():
        project.title = form.title.data
        project.thumbnail = form.thumbnail.data
        project.image_url = form.image_url.data
        project.website_url = form.website_url.data
        project.github_url = form.github_url.data
        project.python = form.python.data
        project.flask = form.flask.data
        project.django = form.django.data
        project.htmlcss = form.htmlcss.data
        project.content = form.content.data
        db.session.commit()
        flash('Your project has been updated!', 'success')
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.title.data = project.title
        form.thumbnail.data = project.thumbnail
        form.image_url.data = project.image_url
        form.website_url.data = project.website_url
        form.github_url.data = project.github_url
        form.python.data = project.python
        form.flask.data = project.flask
        form.django.data = project.django
        form.htmlcss.data = project.htmlcss
        form.content.data = project.content
    return render_template('project.html', form=form, legend='Edit Project')


@app.route("/project/<project_id>/delete", methods=['POST', 'GET'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    if current_user.username != 'Eshan':
        abort(403)
    db.session.delete(project)
    db.session.commit()
    flash('Your project has been deleted!', 'success')
    return redirect(url_for('home'))


@ app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        flash("You are already logged in", "info")
        return redirect(url_for("home"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get("next")
            flash("Login Successful. You have been logged in.", "success")
            return redirect(next_page) if next_page else redirect(url_for("home"))
        else:
            flash("Login Unsuccessful. Please check email and password", "danger")
    return render_template('login.html', form=form)


@ app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route("/s")
def short_url_hp_redirect():
    return redirect(f"https://url.eshan.dev/")

@app.route("/s/<shorturl>")
def short_url_redirect(shorturl):
    return redirect(f"https://url.eshan.dev/{shorturl}")

if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0')
