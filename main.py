from flask import Flask, request

import login

app = Flask(__name__)

@app.route("/authenticate", methods=["POST"])
def login_user():
    return login.login_user(request=request)
    
app.run(debug=True)