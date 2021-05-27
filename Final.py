from flask import Flask, request, jsonify, session, redirect, url_for, render_template
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import jwt
from functools import wraps
import sqlite3
import os
import hashlib
import random


app = Flask(__name__)
secret_key = app.secret_key = os.urandom(16)
domen_name = 'http://127.0.0.1:5000/'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lib.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Users(db.Model):
    usersid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, nullable=False, unique=True)
    password = db.Column(db.BLOB, nullable=False)  # LargeBinary

    def __repr__(self):
        return f'<Users {self.id}>'


class Link(db.Model):
    shortlinkid = db.Column(db.Integer, primary_key=True)
    longlinkid = db.Column(db.Integer, db.ForeignKey('Long_link.longlinkid'), nullable=False)
    users_id = db.Column(db.Integer, db.ForeignKey('users.usersid'), nullable=False)
    short_link = db.Column(db.Text, nullable=False)
    count_redirect = db.Column(db.Integer, nullable=True)
    link_status = db.Column(db.Integer, nullable=True)

    def __repr__(self):
        return f'<Link {self.id}>'


class Long_link(db.Model):
    longlinkid = db.Column(db.Integer, primary_key=True)
    long_link = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<Long_link {self.id}>'


class Readble_link(db.Model):
    readble_link_id = db.Column(db.Integer, nullable=False, unique=True, primary_key=True)
    link_id = db.Column(db.Integer, db.ForeignKey('users.linkid'), nullable=False, unique=True)
    link_name = db.Column(db.Text, nullable=False, unique=True)

    def __repr__(self):
        return '<Readble_link %r>' % self.id





@app.route('/')
@app.route('/home')
def index():
    return render_template("index.html")


@app.route('/login')
def login():
    return render_template("Login.html")


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/posts')
def posts():
    articles = Article.query.order_by(Article.date.desc()).all()
    return render_template("posts.html", articles=articles)


@app.route('/posts/<int:id>')
def post_detail(id):
    article = Article.query.get(id)
    return render_template("post_detail.html", article=article)


@app.route('/create-article', methods=['POST', 'GET'])
def create_article():
    if request.method == "POST":
        title = request.form['title']
        intro = request.form['intro']
        text = request.form['text']

        article = Article(title=title, intro=intro, text=text)
        try:
            db.session.add(article)
            db.session.commit()
            return redirect('/posts')
        except:
            return "При добавлении статьи произошла ошибка"
    else:
        return render_template("create-article.html")


if __name__=="__main__":
    app.run(debug=False)

