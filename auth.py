from flask import Flask, request, jsonify, session, redirect, make_response
from flask_sqlalchemy import SQLAlchemy
import jwt
from functools import wraps
import sqlite3
import os
from random import randint, choice
import bcrypt
from hashlib import md5


app = Flask(__name__)
secret_key = app.secret_key = os.urandom(16)
DATABASE = 'lib.db'

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
        token = request.cookies.get('token')
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
            headers = {
                "typ": "JWT",
                "alg": "HS256"
            }
            payloads = {
                "username": username
            }
            try:

                pswd = Users.query.filter_by(username=username).first()
                password = pswd.password

                hash_passwd = bcrypt.checkpw(passwd.encode(), password)
                if passwd is not None and hash_passwd is True:
                    token = jwt.encode(payload=payloads, key=secret_key, algorithm="HS256", headers=headers)
                    res = make_response(jsonify({"token": token}))
                    res.set_cookie(key='token', value=token)
                else:
                    return jsonify({"message": "Неверное имя пользователя или пароль"}), 403
            except:
                return jsonify({"message": f"Пользователя с именем {username} не существует"}), 403
        else:
            return jsonify({"message": "Введите имя пользователя и пароль"}), 403
    return res

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
        token = request.cookies.get('token')
        link_status = data['link_status']
        if short_link == "":
            short_link = make_short_link()
        try:

            username = jwt.decode(token, secret_key, 'HS256')
            username = username['username']
            usr = Users.query.filter_by(username=username).first()
            user_id = usr.id
            # dbllink = longlink.query.filter_by(long_link=long_link).first()
            # dbllinkid = dbllink.id
            # usrdbllnk = Link.query.filter_by(users_id=user_id, link_status=link_status, longlink_id=dbllinkid).first()
            # double_long_link = usrdbllnk.long_link
            # print(double_long_link)

            #user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username['username'],)).fetchone()[0]
            #double_long_link = db.execute('SELECT long_link FROM link WHERE long_link = ? AND user_id = ? AND link_status = ?', (long_link, user_id, link_status)).fetchone()
            double_long_link = None


            if double_long_link is not None:
                message = jsonify({"message": "Данная ссылка уже была сокращена вами ранее. Вы можете редактировать ее в личном кабинете"})
            else:
                #  Проверка на двойную ссылку
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
        token = request.cookies.get('token')
        username = jwt.decode(token, secret_key, "HS256")
        try:
            usr = Users.query.filter_by(username=username).first()
            user_id = usr.id
            lnk = Link.query.filter_by(users_id=user_id).first()
            link_id = lnk.id
            long_linkid = lnk.longlink_id
            lnkid = Link.query.filter_by(id=long_linkid).first()
            long_link = lnkid.long_link
            short_link = lnk.short_link
            link_status = lnk.link_status
            count_redirect = lnk.count_redirect
            for row in req:
                data = {}
                data['link_id'] = link_id
                data['long_link'] = long_link
                data['short_link'] = short_link
                data['link_status'] = link_status
                data['count_redirect'] = count_redirect
                dat.append(data)
        except:
            return jsonify({"message": "Что-то пошло не так"})
        return jsonify(dat)

@app.route("/removelink", methods=['DELETE'])
@check_token
def remove_link():
    if request.method == "DELETE":
        token = request.cookies.get('token')
        username = jwt.decode(token, secret_key, "HS256")
        data = request.get_json()
        short_link = data['short_link']
        try:
            usr = Users.query.filter_by(username=username).first()
            user_id = usr.id
            lnkusrid = Link.query.filter_by(short_link=short_link).first()
            link_user_id = lnkusrid.users_id

            if link_user_id == user_id:
                delete = Link(short_link=short_link, users_id=user_id)
                db.session.delete(delete)
                db.session.commit()
            else:
                return jsonify({"message": "Вы не являетесь владельцем этой короткой ссылки"})
        except:
            return jsonify({"message": "Что-то пошло не так"})
        return jsonify({f"{short_link}": "Ссылка удалена"})

@app.route("/updatelink", methods=['PATCH'])
@check_token
def update_link():
    if request.method == 'PATCH':
        token = request.cookies.get('token')
        username = jwt.decode(token, secret_key, "HS256")
        data = request.get_json()
        link_id = data['link_id']
        short_link = data['short_link']
        link_status = data['link_status']
        try:
            conn = sqlite3.connect(DATABASE)
            db = conn.cursor()

            usr = Users.query.filter_by(username=username).first()
            user_id = usr.id
            lnkusrid = Link.query.filter_by(link_id=link_id).first()
            link_user_id = lnkusrid.users_id
            if link_user_id == user_id:
                if short_link == "":
                    short_link = make_short_link()
                    db.execute('UPDATE link SET short_link = ? WHERE link_id = ? AND user_id = ?', (short_link, link_id, user_id))
                elif 8 < len(short_link) < 12:# БЫЛО БЫ НЕПЛОХО ВАЛИДАТОР НАПИСАТЬ чтобы не было коротких ссылок типа @@@@@@@@@@@@@
                    db.execute('UPDATE link SET short_link = ? WHERE link_id = ? AND user_id = ?', (short_link, link_id, user_id))
                if link_status == 0 or link_status == 1 or link_status == 2:
                    db.execute('UPDATE link SET link_status = ? WHERE link_id = ? AND user_id = ?', (link_status, link_id, user_id))
                conn.commit()
                return jsonify({"Ссылка "+f"{link_id}": "Успешно обновлена"}), 201
            else:
                return jsonify({"message": "Вы не являетесь владельцем этой короткой ссылки"})
        except:
            return jsonify({"message": "Что-то пошло не так"})


@app.route('/<short_link>', methods=['GET'])
def link(short_link):
    try:
        token = request.cookies.get('token')
        if not token:
            lnksts = Link.query.filter_by(short_link=short_link).first()
            link_status = lnksts.link_status
            if link_status == 0:
                lnk = Link.query.filter_by(short_link=short_link).first()

                lnglink = lnk.long_link

                linkid = lnk.link_id
                count = red_count(linkid)
                print(count)
                Link.query.filter_by(link_id=linkid).update({'count_redirect': count})
                db.session.commit()
                return redirect(lnglink, code=302)
            else:
                return jsonify({"message": "Данная ссылка имеет ограниченный доступ, авторизуйтесь или зарегистрируйтесь"})
        try:
            username = jwt.decode(token, secret_key, "HS256")
            #  проверка на юзер айди
            lnk = Link.query.filter_by(short_link=short_link).first()
            link_status = lnk.link_status

            if link_status == 0 or link_status == 1:
                    link = db.execute('SELECT long_link, link_id FROM link WHERE short_link = ?', (short_link,)).fetchone()

                    lnk = Link.query.filter_by(short_link=short_link).first()

                    lnglink = lnk.long_link

                    linkid = lnk.link_id
                    count = red_count(linkid)
                    Link.query.filter_by(link_id=linkid).update({'count_redirect': count})
                    db.session.commit()

                    return redirect(link[0], code=302)
            elif link_status == 3:
                # переделать
                    usr = Users.query.filter_by(username=username).first()
                    user_id = usr.id
                    lnkusrid = Link.query.filter_by(short_link=short_link, users_id=user_id).first()
                    link_user_id = lnkusrid.id
                    if link_user_id == user_id:


                        lnglnk = Longlink.query.filter_by(short_link=short_link, users_id=user_id).first()
                        long_link = lnglnk.long_link

                        link = db.execute('SELECT long_link, link_id FROM link WHERE short_link = ? AND user_id = ?', (short_link, user_id)).fetchone()

                        lnk = Link.query.filter_by(short_link=short_link).first()
                        lnglink = lnk.long_link
                        linkid = lnk.link_id
                        count = red_count(linkid)
                        Link.query.filter_by(link_id=linkid).update({'count_redirect': count})
                        db.session.commit()
                        return redirect(link[0], code=302)
                    else:
                        return jsonify({"message": "Данная ссылка имеет ограниченный доступ"})
        except:
            return jsonify({"message": "Invalid token. Please login"})
    except:
        return jsonify({"message": "Что-то пошло не так 2!"})
    

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
            lnk = Link.query.filter_by(short_link=short_link).first()
            link = lnk.short_link

            if link is None:
                marker = False
        except:
            return jsonify({'message': 'Что-то пошло не так 1 !'})
    return short_link

def red_count(link_id):
    cnt = Users.query.filter_by(link_id=link_id).first()
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
