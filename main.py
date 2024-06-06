from flask import Flask, render_template, url_for, redirect, flash, abort
from flask_bootstrap import Bootstrap5
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField, SelectField
from wtforms.validators import DataRequired
from discord_webhook import DiscordWebhook, DiscordEmbed
import os
import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('API_KEY')
Bootstrap5(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///user.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# Create a User table for all events
class Event(db.Model):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    time: Mapped[str] = mapped_column(String(250), nullable=False)
    ticket: Mapped[str] = mapped_column(String(250), nullable=True)
    # img_url: Mapped[str] = mapped_column(String(250), nullable=False)


# Create a User table for all your registered users
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))


with app.app_context():
    db.create_all()


# Create an admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


# Forms
class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    phone = StringField('Phone', validators=[DataRequired()])
    subject = SelectField('Subject', choices=[('Bottle Service', 'VIP Bottle Service'), ('Rental', 'Rentals'), ('other', 'Other')])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Submit')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')


class AddEventForm(FlaskForm):
    title = StringField('Event', validators=[DataRequired()])
    date = StringField('Date', validators=[DataRequired()])
    time = StringField('Time', validators=[DataRequired()])
    ticket = StringField('Ticket')
    submit = SubmitField('Add Event')


# webhook
def send_webhook(name, email, phone, subject, message):
    webhook = DiscordWebhook(
        url=os.environ.get('WEBHOOK'))
    embed = DiscordEmbed(title="**Contact Info**", color='551A8B')
    embed.set_author(name="Contact Form Response Received!",
                     icon_url="https://scontent-lax3-1.cdninstagram.com/v/t51.2885-19/366123414_1412892982658354_99722523401580637_n.jpg?stp=dst-jpg_s320x320&_nc_ht=scontent-lax3-1.cdninstagram.com&_nc_cat=102&_nc_ohc=SctjHjwqnxcQ7kNvgFqH-M9&edm=AOQ1c0wBAAAA&ccb=7-5&oh=00_AYAmn-zDJDzNmYkzEV0riT8cqLBCrHCG5TzIYjO-qtzxIA&oe=6661CDDE&_nc_sid=8b3546")
    embed.set_footer(text='Time Created')
    embed.add_embed_field(name="Name", value=f"{name}")
    embed.add_embed_field(name="Email", value=f"{email}", inline=True)
    embed.add_embed_field(name="Phone", value=f"{phone}", inline=False)
    embed.add_embed_field(name="Subject", value=f"{subject}", inline=False)
    embed.add_embed_field(name="Message", value=f"{message}", inline=False)
    embed.set_thumbnail(
        url="https://t4.ftcdn.net/jpg/05/25/22/63/360_F_525226337_x7lLRcnU08vDLkijRwgcbaIs8zCfDktC.jpg")
    embed.set_timestamp()
    webhook.add_embed(embed)
    webhook.execute()


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        # Check if user email is already present in the database.
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        # This line will authenticate the user with Flask-Login
        login_user(new_user)
        return redirect(url_for("home"))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/', methods=["GET", "POST"])
def home():
    year = datetime.datetime.now().year
    form = ContactForm()
    result = db.session.execute(db.select(Event))
    events = result.scalars().all()
    if form.validate_on_submit():
        send_webhook(form.name.data, form.email.data, form.phone.data, form.subject.data, form.message.data)
        flash('Your message has been sent.')
        return redirect(url_for('home') + '#section_5')
        # return render_template("index.html", msg_sent=True, form=form, all_events=events)
    return render_template('index.html', form=form, all_events=events, year=year)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        # Note, email in db is unique so will only have one result.
        user = result.scalar()
        # Email doesn't exist
        if not user:
            flash("That email or password does not exist, please try again.")
            return redirect(url_for('login'))
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('That email or password does not exist, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('home'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@admin_only
@app.route('/add-event', methods=["GET", "POST"])
def add_event():
    form = AddEventForm()
    if form.validate_on_submit():
        event_title = form.title.data
        event_date = form.date.data
        event_time = form.time.data
        if form.ticket.data:
            event_ticket = form.ticket.data
        else:
            event_ticket = None
        new_event = Event(
            title=event_title,
            date=event_date,
            time=event_time,
            ticket=event_ticket,
        )
        db.session.add(new_event)
        db.session.commit()
        return redirect(url_for('home')+'#section_2')
    return render_template('add_events.html', form=form, current_user=current_user)


@app.route("/edit-event/<int:event_id>", methods=["GET", "POST"])
@admin_only
def edit_event(event_id):
    event = db.get_or_404(Event, event_id)
    edit_form = AddEventForm(
        title=event.title,
        date=event.date,
        time=event.time,
        ticket=event.ticket,
    )
    if edit_form.validate_on_submit():
        event.title = edit_form.title.data
        event.date = edit_form.date.data
        event.time = edit_form.time.data
        event.ticket = edit_form.ticket.data
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("add_events.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:event_id>")
@admin_only
def delete_event(event_id):
    event_to_delete = db.get_or_404(Event, event_id)
    db.session.delete(event_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=False)
