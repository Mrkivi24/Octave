from flask import Flask, render_template, request, redirect, url_for, session, Response
import sqlite3
from datetime import datetime
import bcrypt
import time
import atexit
import signal

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DB_PATH = 'database/chatroom.db'

@app.route('/')
def home():
    return render_template('login.html')

# Helper function to interact with SQLite
def query_db(query, args=(), one=False):
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(query, args)
        rv = cur.fetchall()
        conn.commit()
        return (rv[0] if rv else None) if one else rv
    
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/info')
def info():
    return render_template('info.html')


# --------------------------------------------
# LOGIN & SIGNUP
# --------------------------------------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        try:
            query_db("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            return redirect(url_for('login'))
        except:
            return "Username already exists."
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # Plain-text password from user
        user = query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):  # Encode to bytes

            session['user_id'] = user[0]
            query_db("UPDATE users SET online = 1 WHERE id = ?", (user[0],))
            return redirect(url_for('chatroom'))
        else:
            return "Invalid credentials."
    return render_template('login.html')



@app.route('/logout')
def logout():
    user_id = session.pop('user_id', None)
    if user_id:
        query_db("UPDATE users SET online = 0 WHERE id = ?", (user_id,))
    return redirect(url_for('login'))


# --------------------------------------------
# LIVE CHATROOM
# --------------------------------------------
@app.route('/chatroom', methods=['GET', 'POST'])
def chatroom():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        message = request.form['message']
        query_db("INSERT INTO chats (user_id, message) VALUES (?, ?)", (session['user_id'], message))

    messages = query_db("""
        SELECT users.username, chats.message
        FROM chats
        JOIN users ON chats.user_id = users.id
        WHERE chats.user_id NOT IN (
            SELECT muted_user_id FROM muted_users WHERE user_id = ?
        )
        ORDER BY chats.id ASC
    """, (session['user_id'],))
    online_users = query_db("SELECT username, typing FROM users WHERE online = 1")
    return render_template('chatroom.html', messages=messages, online_users=online_users)


@app.route('/chat_stream')
def chat_stream():
    def stream():
        last_id = 0
        while True:
            messages = query_db("""
                SELECT chats.id, users.username, chats.message
                FROM chats
                JOIN users ON chats.user_id = users.id
                WHERE chats.id > ?
                ORDER BY chats.id ASC
            """, (last_id,))
            if messages:
                for message in messages:
                    yield f"id: {message[0]}\ndata: {message[1]}: {message[2]}\n\n"
                    last_id = message[0]
            time.sleep(1)

    return Response(stream(), content_type='text/event-stream', headers={"X-Accel-Buffering": "no"})


# --------------------------------------------
# FORUM
# --------------------------------------------
@app.route('/forum', methods=['GET', 'POST'])
def forum():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        query_db("INSERT INTO forums (user_id, title, content) VALUES (?, ?, ?)", (session['user_id'], title, content))

    forums = query_db("""
        SELECT forums.id, users.username, forums.title, forums.content, forums.timestamp
        FROM forums
        JOIN users ON forums.user_id = users.id
        ORDER BY forums.timestamp DESC
    """)
    return render_template('forum.html', forums=forums)


@app.route('/forum/<int:forum_id>', methods=['GET', 'POST'])
def forum_detail(forum_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Handle comment submission
    if request.method == 'POST':
        comment = request.form['comment']
        if comment.strip():  # Ensure comment is not empty
            query_db("INSERT INTO comments (forum_id, user_id, comment) VALUES (?, ?, ?)",
                     (forum_id, session['user_id'], comment))
        else:
            return "Comment cannot be empty.", 400

    # Retrieve the forum post
    forum = query_db("""
        SELECT forums.id, forums.title, forums.content, users.username, forums.timestamp
        FROM forums
        JOIN users ON forums.user_id = users.id
        WHERE forums.id = ?
    """, (forum_id,), one=True)

    if not forum:
        return "Forum not found.", 404

    # Retrieve comments for the forum
    comments = query_db("""
        SELECT users.username, comments.comment, comments.timestamp
        FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE comments.forum_id = ?
        ORDER BY comments.timestamp ASC
    """, (forum_id,))
    
    return render_template('forum_detail.html', forum=forum, comments=comments)



# --------------------------------------------
# MUTE FUNCTION
# --------------------------------------------
@app.route('/mute_user', methods=['POST'])
def mute_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    muted_username = request.form['username']
    muted_user = query_db("SELECT id FROM users WHERE username = ?", (muted_username,), one=True)
    if muted_user:
        query_db("INSERT INTO muted_users (user_id, muted_user_id) VALUES (?, ?)", (session['user_id'], muted_user[0]))
    return redirect(url_for('chatroom'))


# --------------------------------------------
# DIRECT MESSAGE
# --------------------------------------------
@app.route('/direct_message/<username>', methods=['GET', 'POST'])
def direct_message_page(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Get the recipient's user ID
    recipient = query_db("SELECT id FROM users WHERE username = ?", (username,), one=True)
    if not recipient:
        return "User not found.", 404

    # Handle sending a message
    if request.method == 'POST':
        message = request.form['message']
        if message.strip():  # Ensure the message is not empty
            query_db("INSERT INTO direct_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)",
                     (session['user_id'], recipient[0], message))

    # Retrieve all messages between the logged-in user and the recipient
    messages = query_db("""
        SELECT
            CASE WHEN sender_id = ? THEN 'You'
                 ELSE (SELECT username FROM users WHERE id = sender_id)
            END AS sender,
            message,
            timestamp
        FROM direct_messages
        WHERE (sender_id = ? AND receiver_id = ?)
           OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    """, (session['user_id'], session['user_id'], recipient[0], recipient[0], session['user_id']))

    return render_template('direct_message.html', recipient=username, messages=messages)

@app.route('/dm_stream/<username>')
def dm_stream(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    def stream():
        last_id = 0
        recipient = query_db("SELECT id FROM users WHERE username = ?", (username,), one=True)
        if not recipient:
            yield "data: User not found.\n\n"
            return

        while True:
            messages = query_db("""
                SELECT direct_messages.id, users.username, direct_messages.message
                FROM direct_messages
                JOIN users ON direct_messages.sender_id = users.id
                WHERE (direct_messages.sender_id = ? AND direct_messages.receiver_id = ?)
                   OR (direct_messages.sender_id = ? AND direct_messages.receiver_id = ?)
                AND direct_messages.id > ?
                ORDER BY direct_messages.id ASC
            """, (session['user_id'], recipient[0], recipient[0], session['user_id'], last_id))
            if messages:
                for message in messages:
                    yield f"id: {message[0]}\ndata: {message[1]}: {message[2]}\n\n"
                    last_id = message[0]
            time.sleep(1)

    return Response(stream(), content_type='text/event-stream', headers={"X-Accel-Buffering": "no"})



#log in user
@app.before_request
def add_logged_in_user():
    session['username'] = get_logged_in_username()

def get_logged_in_username():
    if 'user_id' in session:
        user = query_db("SELECT username FROM users WHERE id = ?", (session['user_id'],), one=True)
        if user:
            return user[0]
    return None

# --------------------------------------------
# UNMUTE FUNCTION
# --------------------------------------------
@app.route('/unmute_user', methods=['POST'])
def unmute_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    unmuted_username = request.form['username']
    unmuted_user = query_db("SELECT id FROM users WHERE username = ?", (unmuted_username,), one=True)
    if unmuted_user:
        query_db("DELETE FROM muted_users WHERE user_id = ? AND muted_user_id = ?", (session['user_id'], unmuted_user[0]))
    return redirect(url_for('chatroom'))




# In your existing code, replace the direct message form action in the chatroom.html file with this:
# <form method="GET" action="{{ url_for('direct_message_page', username=user[0]) }}">
#  <button type="submit">Direct Message</button>
# </form>



if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
