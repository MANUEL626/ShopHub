import toml
from flask import flash


def get_secret_key():
    with open("secret.toml", "r") as f:
        config = toml.load(f)
    return config["app"]["secret_key"]


def verify_password(password, confirm_password):
    if password != confirm_password:
        flash(category='error', message='Passwords do not match')
        return False
    elif len(password) < 8:
        flash(category='error', message='The password is too short')
        return False
    elif not any(char.isalpha() for char in password):
        flash(category='error', message='The password must contain at least one letter')
        return False
    return True


def verify_user(existing_name):
    if existing_name:
        flash(category='error', message='this username is already taken')
        return False
    return True


def verify_name(name):
    if len(name) < 3:
        flash(category='error', message='The username is too short')
        return False
    return True


def verify_mail(existing_mail):
    if existing_mail:
        flash(category='error', message='this email is already taken')
        return False
    return True

