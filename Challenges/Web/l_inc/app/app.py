from flask import Flask, render_template, request, make_response, redirect, url_for, render_template_string

import pickle
from base64 import b64encode, b64decode

app = Flask(__name__)


class User:
    def __init__(self, name, vip=False):
        self.name = name
        self.vip = vip

    def isVip(self):
        return self.vip


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        resp = make_response(redirect(url_for('home')))
        name = request.form.get('name', default='')
        if name == '':
            return '<h1>Please enter a valid name</h1>'
        user = User(name)
        resp.set_cookie('user', b64encode(pickle.dumps(user)))
        return resp
    return render_template('index.html')


@app.route('/home')
def home():
    user = request.cookies.get('user', default='')
    if user == '':
        return redirect(url_for('index'))
    try:
        user = pickle.loads(b64decode(user))
        if user.isVip():
            temp = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VIP - L Inc.</title>
</head>
<body>
    <h1>Hello, dear {}</h1>
    <p>You are our VIP customer, there will be a specially-assigned person to serve you later.</p>
</body>
</html>'''.format(user.name)
            return render_template_string(temp)
        else:
            return render_template('home.html', name=user.name)
    except Exception as e:
        resp = make_response(redirect(url_for('index')))
        resp.delete_cookie('user')
        return resp


@app.route('/vip')
def become():
    return render_template('vip.html')


if __name__ == '__main__':
    app.run()
