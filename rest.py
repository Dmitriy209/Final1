from flask import Flask, request, jsonify, session, redirect, make_response
from flask_sqlalchemy import SQLAlchemy
import jwt
from functools import wraps
import sqlite3
import os
from random import randint, choice
import bcrypt
from hashlib import md5
from datetime import timedelta

app = Flask(__name__)
secret_key = app.secret_key = os.urandom(16)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=200)
DATABASE = 'proj.db'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lib.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, nullable=False, unique=True)
    password = db.Column(db.BLOB, nullable=False)  # LargeBinary

    def __repr__(self):
        return f'<Users {self.id}>'


class longlink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    long_link = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<longlink {self.id}>'


class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    longlink_id = db.Column(db.Integer, db.ForeignKey('longlink.id'), nullable=False)
    users_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    short_link = db.Column(db.Text, nullable=False)
    count_redirect = db.Column(db.Integer, nullable=True)
    link_status = db.Column(db.Integer, nullable=True)

    def __repr__(self):
        return f'<Link {self.id}>'


def check_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = session.get('token')
        if not token:
            return jsonify({"message": "Missing token"}), 403
        try:
            data = jwt.decode(token, secret_key, "HS256")
        except:
            return jsonify({"message": "Invalid token"}), 403
        return func(*args, **kwargs)
    return wrapped

@app.route("/login", methods=['GET'])
def login():
    if request.method == 'GET':
        data = request.get_json()
        username = data['username']
        passwd = data['password']
        if username != '' and passwd != '':
            headers = {"typ": "JWT", "alg": "HS256"}
            payloads = {"username": username}
            try:
                pswd = Users.query.filter_by(username=username).first()
                password = pswd.password
                hash_passwd = bcrypt.checkpw(passwd.encode(), password)
                if passwd is not None and hash_passwd is True:
                    token = jwt.encode(payload=payloads, key=secret_key, algorithm="HS256", headers=headers)
                    session["username"] = username
                    session["token"] = token
                    res = make_response(jsonify({"token": token}))
                    res.set_cookie(key='token', value=token)
                else:
                    return jsonify({"message": "Неверное имя пользователя или пароль"}), 403
            except:
                return jsonify({"message": f"Пользователя с именем {username} не существует"}), 403
        else:
            return jsonify({"message": "Введите имя пользователя и пароль"}), 403
    return res, 200

@app.route("/logout", methods=["GET"])
def logout():
    name = session['username']
    session.pop("username", None)
    session.pop("token", None)
    return jsonify({"message": f"{name} - закрыта"})

@app.route("/register", methods=['POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data['username']
        passwd = data['password']
        if username != '' and passwd != '':
            hash_passwd = bcrypt.hashpw(passwd.encode(), bcrypt.gensalt())
            headers = {
                "typ": "JWT",
                "alg": "HS256"
            }
            payloads = {
                "username": username
            }
            token = jwt.encode(payload=payloads, key=secret_key, algorithm="HS256", headers=headers)
            res = make_response(jsonify({"token": token}))
            res.set_cookie(key='token', value=token)
            try:
                users = Users(username=username, password=hash_passwd)
                db.session.add(users)
                db.session.commit()
            except:
                return "Пользователь с таким именем уже зарегистрирован. Попробуйте использовать другое имя.",  403
        else:
            return jsonify({"message": "Введите имя пользователя и пароль"}), 403
        return res


@app.route("/make_link", methods=['POST'])
@check_token
def make_link():
    if request.method == 'POST':
        data = request.get_json()
        long_link = data['long_link']
        short_link = data['short_link']
        token = session.get('token')
        link_status = data['link_status']
        if short_link == "":
            short_link = make_short_link()
        try:

            conn = sqlite3.connect(DATABASE)
            db = conn.cursor()

            username = jwt.decode(token, secret_key, 'HS256')
            usr = Users.query.filter_by(username=username).first()
            user_id = usr.id
            #####
            double_long_link = db.execute('SELECT long_link FROM link WHERE long_link = ? AND user_id = ? AND link_status = ?', (long_link, user_id, link_status)).fetchone()
            #####
            if double_long_link is not None:
                return jsonify({"message": "Данная ссылка уже была сокращена вами ранее. Вы можете редактировать ее в личном кабинете"})
            else:
                lnglnk = longlink.query.filter_by(long_link=long_link).first()
                longlnk = lnglnk.long_link
                if long_link != longlnk:
                    lnglnk = longlink(long_link=long_link)
                    db.session.add(lnglnk)
                    db.session.commit()
                lnglnk = longlink.query.filter_by(long_link=long_link).first()
                lnglnkid = lnglnk.id
                link = Link(short_link=short_link, users_id=user_id, link_status=link_status, longlink_id=lnglnkid)
                db.session.add(link)
                db.session.commit()
                return jsonify({"long_link": long_link, "short_link": short_link, "link_status": link_status})
        except:
            return jsonify({"message": "Что-то пошло не так 2 !"})
 
@app.route("/show_links", methods=['GET'])
@check_token
def show_links():
    if request.method == 'GET':
        dat = []
        token = session.get('token')
        username = jwt.decode(token, secret_key, "HS256")
        usr = Users.query.filter_by(username=username).first()
        user_id = usr.id
        try:
            lnk = Link.query.filter_by(users_id=user_id).all()
            for row in lnk:
                data = {}
                data['link_id'] = lnk[row].id
                long_linkid = lnk[row].longlink_id
                lnkid = longlink.query.filter_by(id=long_linkid).first()
                data['long_link'] = lnkid[row].long_link
                data['short_link'] = lnk[row].short_link
                data['link_status'] = lnk[row].link_status
                data['count_redirect'] = lnk[row].count_redirect
                dat.append(data)
        except:
            return jsonify({"message": "Что-то пошло не так"})
        return jsonify(dat)

@app.route('/<short_link>', methods=['GET', 'DELETE', 'PATCH'])
def link(short_link):
    if request.method == "GET":
        try:
            token = session.get('token')
            if not token:
                lnk = Link.query.filter_by(short_link=short_link).first()
                link_status = lnk.link_status
                #  Решить проблему дублирования коротких ссылок
                if link_status == 0:
                    lnk = Link.query.filter_by(short_link=short_link).first()
                    longlink_id = lnk.longlink_id
                    lnglnk = longlink.query.filter_by(longlink_id=longlink_id).first()
                    long_link = lnglnk.long_link
                    link_id = lnk.id
                    count = red_count(link_id)
                    print(count)
                    Link.query.filter_by(id=link_id).update({'count_redirect': count})
                    db.session.commit()
                    return redirect(long_link, code=302)
                else:
                    return jsonify({"message": "Данная ссылка имеет ограниченный доступ, авторизуйтесь или зарегистрируйтесь"})
            try:
                username = jwt.decode(token, secret_key, "HS256")
                usr = Users.query.filter_by(username=username).first()
                user_id = usr.id
                lnk = Link.query.filter_by(short_link=short_link).first()
                link_status = lnk.link_status
                if link_status == 0 or link_status == 1:
                    #  Дублирование короткой ссылки
                    link_id = lnk.id
                    longlink_id = lnk.longlink_id
                    lnglnk = longlink.query.filter_by(longlink_id=longlink_id).first()
                    long_link = lnglnk.long_link
                #    link = db.execute('SELECT long_link, link_id FROM link WHERE short_link = ?', (short_link,)).fetchone()
                    count = red_count(link_id)
                    Link.query.filter_by(id=link_id).update({'count_redirect': count})
                    db.session.commit()
                    return redirect(long_link, code=302)
                elif link_status == 3:
                    lnk = Link.query.filter_by(short_link=short_link, users_id=user_id).first()
                    link_id = lnk.id
                    longlink_id = lnk.longlink_id
                    lnglnk = longlink.query.filter_by(longlink_id=longlink_id).first()
                    long_link = lnglnk.long_link
                    count = red_count(link_id)
                    Link.query.filter_by(id=link_id).update({'count_redirect': count})
                    db.session.commit()
                    return redirect(long_link, code=302)
                else:
                    return jsonify({"message": "Данная ссылка имеет ограниченный доступ"})
            except:
                return jsonify({"message": "Invalid token. Please login"})
        except:
            return jsonify({"message": "Что-то пошло не так 2!"})
    if request.method == "DELETE":
        token = session.get('token')
        if token is None:
            return jsonify({"message": "Missing token"})
        try:
            data = jwt.decode(token, secret_key, "HS256")
        except:
            return jsonify({"message": "Invalid token"}), 403
        username = jwt.decode(token, secret_key, "HS256")
        try:
            usr = Users.query.filter_by(username=username).first()
            user_id = usr.id
            delete = Link(short_link=short_link, users_id=user_id)
            db.session.delete(delete)
            db.session.commit()
        except:
            return jsonify({"message": "Пройдите авторизацию"})
        return jsonify({f"{short_link}": "Ссылка удалена"})
    if request.method == "PATCH":
        token = session.get('token')
        if token is None:
            return jsonify({"message": "Missing token"}), 403
        try:
            data = jwt.decode(token, secret_key, "HS256")
        except:
            return jsonify({"message": "Invalid token"}), 403
        username = jwt.decode(token, secret_key, "HS256")
        data = request.get_json()
        link_status = data['link_status']
        new_short_link = data['new_short_link']
        try:           #  ЧТО тут происходит?
            usr = Users.query.filter_by(username=username).first()
            user_id = usr.id
            if new_short_link == "":
                new_short_link = make_short_link()
                Link.query.filter_by(short_link=short_link, users_id=user_id).update({'short_link': new_short_link})
                db.session.commit()
            elif 8 < len(new_short_link) < 12:# БЫЛО БЫ НЕПЛОХО ВАЛИДАТОР НАПИСАТЬ чтобы не было коротких ссылок типа @@@@@@@@@@@@@
                Link.query.filter_by(short_link=short_link, users_id=user_id).update({'short_link': new_short_link})
                db.session.commit()
            if link_status == 0 or link_status == 1 or link_status == 2 and link_status != "":
                Link.query.filter_by(short_link=short_link, users_id=user_id).update({'link_status': link_status})
                db.session.commit()
            return jsonify({"Ссылка "+f"{short_link}": "Успешно обновлена"}), 201
        except:
            return jsonify({"message": "Пройдите авторизацию"})


def make_short_link():
    marker = True
    while marker == True:
        try:
            arr_link = []
            alphavit = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
            count = randint(8, 12)
            [arr_link.append(choice(alphavit)) for i in range(100)]
            num = ''.join(arr_link)
            short_link = md5(num.encode('utf-8')).hexdigest()[:count]
            print(short_link)
            ##############
            #  Надо добавить Userid, у нас могут быть 2 одинаковые короткие ссылки у разных пользователей
            lnk = Link.query.filter_by(short_link=short_link).first()
            missing = Link.query.filter_by(short_link=lnk.short_link).first()
            ###############
            #  link = db.execute('SELECT short_link FROM link WHERE short_link = ?', (short_link,)).fetchone() Что тут происходит?
            if missing is None:
                marker = False
        except:
            return jsonify({'message': 'Что-то пошло не так 1 !'})
    return short_link

def red_count(link_id):
    cnt = Link.query.filter_by(id=link_id).first()
    count = cnt.count_redirect
    print(count)
    if count is None:
        count = 1
        return count
    else:
        count = count + 1
        return count

if __name__=="__main__":
    app.run(debug=True)