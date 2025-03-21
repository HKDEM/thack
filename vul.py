import os
import subprocess
import pickle
from flask import Flask, request

app = Flask(__name__)

@app.route('/command_injection')
def command_injection():
    user_input = request.args.get('command')
    subprocess.call(user_input, shell=True)  # Kritik Komut Enjeksiyonu!
    return "Komut çalıştırıldı"

@app.route('/path_traversal')
def path_traversal():
    filename = request.args.get('filename')
    filepath = os.path.join("/files", filename)  # Kritik Yol Geçişi!
    with open(filepath, 'r') as f:
        content = f.read()
    return content

@app.route('/deserialization', methods=['POST'])
def deserialization():
    data = request.data
    user_data = pickle.loads(data)  # Kritik Güvenli Olmayan Serileştirme!
    return str(user_data)

@app.route('/sql_injection')
def sql_injection():
    user_input = request.args.get('username')
    # Varsayımsal veritabanı sorgusu (gerçek bir veritabanı yok)
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"  # Kritik SQL Enjeksiyonu!
    return query

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

