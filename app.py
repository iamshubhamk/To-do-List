import sqlite3 as sql
from flask import Flask, request, redirect, url_for, render_template, session
from os import path
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'
ROOT = path.dirname(path.realpath(__file__))

def create_db():
    db_path = path.join(ROOT, 'database.db')
    with sql.connect(db_path) as con:
        cur = con.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author_id INTEGER,
                FOREIGN KEY (author_id) REFERENCES users (id)
            )
        ''')

@app.route('/')
def index():
    db_path = path.join(ROOT, 'database.db')
    with sql.connect(db_path) as con:
        cur = con.cursor()
        cur.execute('SELECT posts.id, title, content, username FROM posts JOIN users ON posts.author_id = users.id')
        posts = cur.fetchall()
    return render_template('index.html', posts=posts)

@app.route('/post/<int:post_id>')
def post(post_id):
    db_path = path.join(ROOT, 'database.db')
    with sql.connect(db_path) as con:
        cur = con.cursor()
        cur.execute('SELECT title, content, username FROM posts JOIN users ON posts.author_id = users.id WHERE posts.id = ?', (post_id,))
        post = cur.fetchone()
    return render_template('post.html', post=post)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db_path = path.join(ROOT, 'database.db')
        with sql.connect(db_path) as con:
            cur = con.cursor()
            cur.execute('SELECT id, password FROM users WHERE username = ?', (username,))
            user = cur.fetchone()
            if user and check_password_hash(user[1], password):
                session['user_id'] = user[0]
                return redirect(url_for('index'))
            else:
                return 'Invalid credentials'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        db_path = path.join(ROOT, 'database.db')
        with sql.connect(db_path) as con:
            cur = con.cursor()
            try:
                cur.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                con.commit()
                return redirect(url_for('login'))
            except sql.IntegrityError:
                return 'Username already exists'
    return render_template('register.html')

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        author_id = session['user_id']
        db_path = path.join(ROOT, 'database.db')
        with sql.connect(db_path) as con:
            cur = con.cursor()
            cur.execute('INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)', (title, content, author_id))
        return redirect(url_for('index'))
    return render_template('create_post.html')

if __name__ == '__main__':
    create_db()
    app.run(debug=True)
