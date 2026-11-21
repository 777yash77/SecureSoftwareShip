import hashlib
import os
import pickle
import subprocess
from flask import Flask, request

app = Flask(__name__)

# Vulnerability 1: Insecure Configuration (DEBUG enabled)
DEBUG = True

# Vulnerability 2: Hardcoded AWS Credentials
AWS_ACCESS_KEY_ID = "AKIA1111222233334444"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


@app.route("/search")
def search():
    user_id = request.args.get("id", "1")
    # Vulnerability 3: SQL Injection via f-string dynamic query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = None  # mock DB cursor
    # cursor.execute(query)
    return f"Executed: {query}"


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Vulnerability 4: Command Injection via os.system
    os.system("ping -c 1 " + host)

    # Vulnerability 5: Command Injection via subprocess with shell=True
    subprocess.Popen(f"nslookup {host}", shell=True)
    return "Ping triggered"


@app.route("/deserialize", methods=["POST"])
def deserialize():
    raw_payload = request.data
    # Vulnerability 6: Insecure Deserialization via pickle
    user_obj = pickle.loads(raw_payload)
    return str(user_obj)


@app.route("/calc")
def calc():
    expression = request.args.get("expr", "1+1")
    # Vulnerability 7: Arbitrary Code Execution via eval()
    res = eval(expression)
    return str(res)


@app.route("/hash")
def hash_pass():
    pwd = request.args.get("pwd", "pass")
    # Vulnerability 8: Weak Cryptographic Hash (MD5)
    hashed = hashlib.md5(pwd.encode()).hexdigest()
    return hashed


if __name__ == "__main__":
    # Vulnerability 9: Binding to 0.0.0.0 (all interfaces)
    app.run(host="0.0.0.0", port=5000, debug=True)
