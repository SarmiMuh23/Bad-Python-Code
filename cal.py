import os
import subprocess
import pickle
import sqlite3
import requests
from flask import Flask, request

app = Flask(__name__)

# Hardcoded credentials (Security issue: Sensitive information exposure)
USERNAME = "admin"
PASSWORD = "password123"

# SQL Injection vulnerability
def get_user_info(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id  # No parameterized query (Vulnerable to SQL Injection)
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

# Insecure Deserialization (Arbitrary code execution risk)
def insecure_deserialization(data):
    return pickle.loads(data)  # Unsafe loading of untrusted data

# Command Injection vulnerability
def execute_command(cmd):
    return subprocess.check_output(cmd, shell=True)  # Unsanitized input in shell command execution

# Unvalidated Redirects and Forwards
@app.route('/redirect')
def unsafe_redirect():
    url = request.args.get('url')
    return requests.get(url).text  # User-controlled URL request (Open Redirect vulnerability)

# Exposing Debug Mode (Information Disclosure)
if __name__ == '__main__':
    app.run(debug=True)  # Debug mode exposes sensitive details in errors