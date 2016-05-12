from flask import Flask, flash, request, redirect, render_template, session
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "thisisasecret"
mysql = MySQLConnector(app,'walldb')

@app.route('/')
def index():
        return render_template('wallindex.html')

@app.route('/login', methods = ['POST'])
def login_form():
        error_count = 0
        if not EMAIL_REGEX.match(request.form['email']):
                flash("Email is not a valid email")
                error_count += 1
        if len(request.form['email']) < 1:
                flash('Login email cannot be empty')
                error_count += 1
        if len(request.form['password']) < 1:
                flash('Password cannot be empty')
                error_count += 1
        if error_count > 0:
                return redirect('/')
        else:
                db = login()
                if(db):
                        match = bcrypt.check_password_hash(db[0]['password'], request.form['password'])
                        if(match):
                                session['active_id'] = db[0]['id']
                                session['active_name'] = db[0]['first_name']
                                return redirect('/userpage')
                else:
                        flash('Email/Password is inccorect')
                        return redirect('/userpage')
def login():
        query = "SELECT id, password, first_name FROM users WHERE email = :email"
        data = { 'email': request.form['email']}
        return mysql.query_db(query, data)


@app.route('/register', methods = ['POST'])
def register():
        error_count = 0
        if not EMAIL_REGEX.match(request.form['email']):
            flash("Email is not a valid email")
            error_count += 1
        if len(request.form['first_name']) < 2:
            flash("First name must be longer than 2 characters")
            error_count += 1
        if not request.form['first_name'].isalpha():
            flash('First name must be only alphabetical letters')
            error_count += 1
        if len(request.form['last_name']) < 2:
            flash('Last name much be only alphabetical letters')
            error_count += 1
        if not request.form['last_name'].isalpha():
            flash('Last name much be only alphabetical letters')
            error_count += 1
        if len(request.form['password']) < 8:
            flash('Password much be at least 8 characters')
        if error_count > 0:
                return redirect('/')
        if error_count == 0:
                query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, NOW(), NOW())"
                data = {
                        'first_name':request.form['first_name'],
                        'last_name':request.form['last_name'],
                        'email':request.form['email'],
                        'password': bcrypt.generate_password_hash(request.form['password'])

                }
                mysql.query_db(query, data)
                return redirect('/')
        else:
                flash('Confirm Password must match password')
                return redirect('/')


@app.route('/logout')
def logout():
            session.clear()
            return redirect('/')

@app.route('/userpage')
def wallpage():
                messages = get_messages()
                comments = get_comments()
                return render_template('userpage.html', messages = messages , comments = comments)

def get_messages():
            query = "SELECT messages.id, first_name, last_name, messages.message, messages.users_id, messages.created_at FROM users LEFT JOIN messages ON users.id = messages.users_id ORDER BY created_at desc"
            return mysql.query_db(query)


def get_comments():
            query = "SELECT first_name, last_name, comments.id, comments.users_id, comments, comments.created_at, comments.messages_id FROM comments LEFT JOIN users ON users.id = comments.users_id ORDER BY created_at desc"
            return mysql.query_db(query)

@app.route('/usermessage/<id>', methods = ['POST'])
def postmessage(id):
                query = "INSERT INTO messages (message, created_at, updated_at, users_id) VALUES (:message, NOW(), NOW(), :active_id)"
                data = {
                        'message' : request.form['messagebox'],
                        'active_id' : session['active_id']
                }
                mysql.query_db(query, data)
                return redirect('/userpage')

@app.route('/usercomment', methods = ['POST'])
def postcomment():
                query = "INSERT INTO comments (comments, created_at, updated_at, users_id, messages_id) VALUES (:comment, NOW(), NOW(), :active_id, :messages_id)"
                data = {
                        'comment' : request.form['commentbox'],
                        'active_id' : session['active_id'],
                        'messages_id' : request.form['messages_id']

                }
                mysql.query_db(query, data)
                return redirect('/userpage')

@app.route('/deletemessage/<messages_id>/<message_users_id>')
def delete_message(messages_id, message_users_id):
            # query that says delete from comments where messages_id = :messages_id
            query2 = "DELETE FROM comments where messages_id = :messages_id"

            query = "DELETE FROM messages WHERE messages.id = :messages_id"
            data = {
                    'messages_id' : messages_id

            }
            mysql.query_db(query2, data)
            mysql.query_db(query, data)
            return redirect('/userpage')

@app.route('/deletecomment/<comment_id>/<comment_user_id>')
def delete_comment(comment_id, comment_user_id):
            query = "DELETE FROM comments WHERE comments.id = :comment_id"
            data = {
                    'comment_id' : comment_id

            }
            mysql.query_db(query, data)
            return redirect('/userpage')


app.run(debug=True)
