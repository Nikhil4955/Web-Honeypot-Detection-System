from flask import Flask, request, render_template_string, redirect, session
import sqlite3, os, re

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB_FILE = 'database.db'

# ----------------------- INIT DB -----------------------

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    attack_type TEXT,
                    input_data TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS blacklist (
                    ip TEXT PRIMARY KEY
                )''')
    conn.commit()
    conn.close()

init_db()

# ------------------ LOG & BLACKLIST --------------------

def log_attack(ip, attack_type, input_data):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("INSERT INTO logs (ip, attack_type, input_data) VALUES (?, ?, ?)", (ip, attack_type, input_data))
    count = conn.execute("SELECT COUNT(*) FROM logs WHERE ip = ?", (ip,)).fetchone()[0]
    if count >= 5:
        conn.execute("INSERT OR IGNORE INTO blacklist (ip) VALUES (?)", (ip,))
    conn.commit()
    conn.close()

def is_blacklisted(ip):
    conn = sqlite3.connect(DB_FILE)
    result = conn.execute("SELECT 1 FROM blacklist WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    return result is not None

# ------------------ DETECTION FUNCTIONS --------------------

def detect_sqli(data):
    sqli_patterns = [
        r"(?i)(\bor\b|\band\b)\s+\d+=\d+",
        r"(?i)union\s+select",
        r"(?i)select\s.+\sfrom",
        r"(?i)insert\s+into",
        r"(?i)update\s+\w+\s+set",
        r"(?i)delete\s+from",
        r"(?i)--", r"#", r"/\*", r"\*/",
        r"(?i)1=1",
        r"(?i)drop\s+table"
    ]
    return any(re.search(p, data) for p in sqli_patterns)

def detect_xss(data):
    xss_patterns = [
        r"(?i)<script.*?>.*?</script>",
        r"(?i)<.*?on\w+\s*=\s*['\"].*?['\"]",
        r"(?i)javascript:",
        r"(?i)<iframe",
        r"(?i)<img.*?src=.*?onerror=",
        r"(?i)<svg.*?onload="
    ]
    return any(re.search(p, data) for p in xss_patterns)

# ------------------ BEFORE REQUEST --------------------

@app.before_request
def block_blacklisted():
    ip = request.remote_addr
    safe_routes = ['/admin-login', '/dashboard', '/blacklist']
    if is_blacklisted(ip) and request.path not in safe_routes:
        return f"""
        <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css'>
        <script>
            alert("🚫 Your IP ({ip}) has been blocked due to repeated suspicious activity.");
        </script>
        <div class='container mt-5'>
            <h1 class='text-danger'>🚫 Access Denied</h1>
            <p>Your IP <strong>{ip}</strong> has been <b>blocked</b> due to suspicious activity like SQL Injection, XSS, or brute-force attempts.</p>
            <p>If you believe this is a mistake, please contact the administrator.</p>
        </div>
        """, 403

# ------------------ ROUTES ----------------------------

@app.route('/')
def home():
    return '''
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <div class="container mt-5">
        <h2 class="text-primary">🛡️ Web Honeypot Project</h2>
        <p class="lead">Simulated system capturing SQLi, XSS, and brute-force attacks.</p>
        <a href="/login" class="btn btn-secondary">🎯 Login</a>
        <a href="/comment" class="btn btn-secondary">💬 Post Comment</a>
    </div>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        combined = f"{username} {password}"

        if detect_sqli(combined):
            log_attack(ip, "SQL Injection", combined)

        if username != 'attacker' or password != 'guessme':
            log_attack(ip, "Brute Force", combined)
            return "<p>Login failed</p><a href='/login'>Try again</a>"

        return redirect('/portal')

    return '''
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <div class="container mt-5">
        <h3>🎯 Login to your account</h3>
        <form method="POST">
            <div class="mb-3"><input class="form-control" name="username" placeholder="Username" required></div>
            <div class="mb-3"><input class="form-control" name="password" type="password" placeholder="Password" required></div>
            <button class="btn btn-danger">Login</button>
        </form>
    </div>
    '''

@app.route('/dashboard')
def dashboard():
    if session.get('user') != 'admin':
        return redirect('/admin-login')

    conn = sqlite3.connect(DB_FILE)
    logs = conn.execute("SELECT ip, attack_type, input_data, timestamp FROM logs ORDER BY timestamp DESC LIMIT 20").fetchall()
    ip_stats = conn.execute("SELECT ip, COUNT(*) FROM logs GROUP BY ip").fetchall()
    type_stats = conn.execute("SELECT attack_type, COUNT(*) FROM logs GROUP BY attack_type").fetchall()
    conn.close()


    ip_labels = [row[0] for row in ip_stats]
    ip_counts = [row[1] for row in ip_stats]
    type_labels = [row[0] for row in type_stats]
    type_counts = [row[1] for row in type_stats]

    # Pie chart 

    html = '''
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <div class="container mt-5">
        <h2 class="text-primary">📊 Attack Logs Dashboard</h2>
        <a href="/blacklist" class="btn btn-warning text-black mb-3 btn-sm">Go to Blacklist IPs</a>


        <div class="row mb-5">
            <div class="col-md-6">
                <h5 class="text-secondary">Attacks per IP</h5>
                <canvas id="ipChart"></canvas>
            </div>
            <div class="col-md-6">
                <h5 class="text-secondary">Attack Type Distribution</h5>
                <canvas id="typeChart"></canvas>
            </div>
        </div>

        {% if logs %}
        <table class="table table-striped">
            <thead><tr><th>IP Address</th><th>Type</th><th>Input</th><th>Timestamp</th></tr></thead>
            <tbody>
            {% for log in logs %}
            <tr>
                <td>{{ log[0] }}</td>
                <td>{{ log[1] }}</td>
                <td>{{ log[2] }}</td>
                <td>{{ log[3] }}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No logs to display.</p>
        {% endif %}
        <a href="/portal" class="btn btn-secondary mt-3">⬅ Back to Portal</a>
    </div>

    <script>
        const ipCtx = document.getElementById('ipChart').getContext('2d');
        new Chart(ipCtx, {
            type: 'pie',
            data: {
                labels: {{ ip_labels | tojson }},
                datasets: [{
                    label: 'Attacks per IP',
                    data: {{ ip_counts | tojson }},
                    backgroundColor: ['#ff6384', '#36a2eb', '#ffcd56', '#4bc0c0', '#9966ff', '#ff9f40']
                }]
            }
        });

        const typeCtx = document.getElementById('typeChart').getContext('2d');
        new Chart(typeCtx, {
            type: 'pie',
            data: {
                labels: {{ type_labels | tojson }},
                datasets: [{
                    label: 'Attack Type Distribution',
                    data: {{ type_counts | tojson }},
                    backgroundColor: ['#4bc0c0', '#ff6384', '#36a2eb', '#9966ff', '#ffcd56', '#ff9f40']
                }]
            }
        });
    </script>
    '''
    return render_template_string(html, logs=logs, ip_labels=ip_labels, ip_counts=ip_counts, type_labels=type_labels, type_counts=type_counts)

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'password':
            session['user'] = 'admin'
            return redirect('/dashboard')
        else:
            return "<p>Admin login failed</p><a href='/admin-login'>Try again</a>"

    return '''
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <div class="container mt-5">
        <h3>🔐 Admin Panel Login</h3>
        <form method="POST">
            <div class="mb-3"><input class="form-control" name="username" placeholder="Admin Username" required></div>
            <div class="mb-3"><input class="form-control" name="password" type="password" placeholder="Password" required></div>
            <button class="btn btn-primary">Login</button>
        </form>
    </div>
    '''

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    ip = request.remote_addr
    if request.method == 'POST':
        comment = request.form['comment']
        if detect_xss(comment):
            log_attack(ip, "XSS", comment)
        return "<p>Comment submitted.</p><a href='/'>Home</a>"

    return '''
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <div class="container mt-5">
        <h3>💬 Leave a Comment</h3>
        <form method="POST">
            <textarea name="comment" class="form-control" rows="4" placeholder="Type your comment here..."></textarea><br>
            <button type="submit" class="btn btn-success">Submit</button>
        </form>
    </div>
    '''


@app.route('/portal')
def portal():
    if session.get('user') != 'admin':
        return redirect('/admin-login')

    html = '''
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>
        .card:hover {
            transform: scale(1.05);
            transition: 0.3s ease;
            box-shadow: 0 0 15px rgba(0,0,0,0.3);
        }
        body {
            background-color: #f4f8fb;
        }
    </style>
    <div class="container mt-5">
        <h2 class="mb-4 text-primary">🎯 Choose Your Portal</h2>
        <div class="row g-4">
            <div class="col-md-4">
                <div class="card shadow">
                    <img src="https://source.unsplash.com/featured/?sports" class="card-img-top" alt="Sports">
                    <div class="card-body">
                        <h5 class="card-title">🏅 Sports Portal</h5>
                        <p class="card-text">Catch up on the latest games, scores, and sports news.</p>
                        <a href="https://www.espn.com" target="_blank" class="btn btn-primary">Go to Sports</a>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card shadow">
                    <img src="https://source.unsplash.com/featured/?movies" class="card-img-top" alt="Movies">
                    <div class="card-body">
                        <h5 class="card-title">🎬 Movie Portal</h5>
                        <p class="card-text">Watch trailers, reviews, and discover new movies.</p>
                        <a href="https://www.imdb.com" target="_blank" class="btn btn-success">Go to Movies</a>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card shadow">
                    <img src="https://source.unsplash.com/featured/?news" class="card-img-top" alt="News">
                    <div class="card-body">
                        <h5 class="card-title">📰 News Portal</h5>
                        <p class="card-text">Stay informed with the latest global and local news.</p>
                        <a href="https://www.bbc.com/news" target="_blank" class="btn btn-warning">Go to News</a>
                    </div>
                </div>
            </div>
        </div>
        <br>
        <a href="/dashboard" class="btn btn-secondary mt-4">📊 View Dashboard</a>
    </div>
    '''
    return render_template_string(html)


@app.route('/blacklist', methods=['GET', 'POST'])
def manage_blacklist():
    if session.get('user') != 'admin':
        return redirect('/admin-login')

    conn = sqlite3.connect(DB_FILE)

    if request.method == 'POST':
        if 'remove_ip' in request.form:
            ip_to_remove = request.form['remove_ip']
            conn.execute("DELETE FROM blacklist WHERE ip = ?", (ip_to_remove,))
        if 'clear_all' in request.form:
            conn.execute("DELETE FROM blacklist")
        conn.commit()

    cursor = conn.execute("SELECT ip FROM blacklist")
    blacklist = cursor.fetchall()
    conn.close()

    html = '''
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <div class="container mt-5">
        <h2 class="text-danger">🚫 Blacklisted IPs</h2>
        {% if blacklist %}
        <table class="table table-bordered">
            <thead><tr><th>IP Address</th><th>Actions</th></tr></thead>
            <tbody>
            {% for entry in blacklist %}
            <tr>
                <td>{{ entry[0] }}</td>
                <td>
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="remove_ip" value="{{ entry[0] }}">
                        <button type="submit" class="btn btn-sm btn-danger">Unblock</button>
                    </form>
                </td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
        <form method="POST">
            <button name="clear_all" value="1" class="btn btn-warning">Clear All</button>
        </form>
        {% else %}
        <p>No blacklisted IPs.</p>
        {% endif %}
        <br><a href="/dashboard" class="btn btn-secondary">⬅ Back to Dashboard</a>
    </div>
    '''
    return render_template_string(html, blacklist=blacklist)

# ------------------ MAIN ------------------------------

if __name__ == '__main__':
    app.run(debug=True)

