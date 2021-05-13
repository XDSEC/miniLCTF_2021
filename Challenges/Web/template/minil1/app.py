from flask import Flask,request,render_template
from ABC import abc
from jinja2 import Template
import re
import base64

key="xdsecminil"

app = Flask(__name__)
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/build",methods=['POST'])
def build():
    data=request.form.get("data")
    code=str(base64.b64decode(data).decode())
    result=abc(key,code)
    print(result)
    if re.findall(r'\'|\.|\+|\|',result):
        return "hack!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    if re.findall(r'os|class|base|init|flag',result):
        return "hack!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    t=Template(result)
    return t.render()

if __name__ == '__main__':
    app.run(host="0.0.0.0",port=5000)
