# 🛡️ Web Honeypot Detection System

A simulated web application built with Flask that detects and logs common cyber attacks such as SQL Injection, Cross-Site Scripting (XSS), and Brute-force login attempts. This honeypot also maintains an IP blacklist, logs attack statistics, and provides an interactive admin dashboard with charts.


## 📦 Features

- ✅ Detects **SQL Injection** patterns in login
- ✅ Detects **XSS** patterns in comment form
- ✅ Logs **brute-force** login attempts
- 📊 **Dashboard** with Chart.js-based pie charts:
  - Attack count by IP
  - Attack type distribution
- 🚫 **Automatic IP blacklisting** after 5+ attacks
- 👮‍♂️ **Admin login & session-based protection**
- 🔄 **Blacklist panel**: unblock or clear all IPs
- 🎭 **Deceptive fake portal** with news, movies, sports links

## 🧠 Attack Detection Logic

### 🔍 SQL Injection
Detects common attack patterns:
- `OR 1=1`, `UNION SELECT`, `--`, `DROP TABLE`, etc.

### ⚠️ XSS
Detects suspicious input like:
- `<script>`, `onerror=`, `javascript:`, `<svg onload=`, etc.

### 🔐 Brute-force
Tracks failed login attempts by IP.


## 🛠️ Installation

### Requirements
- Python 3.8+
- Flask

### Steps

```bash
git clone https://github.com/your-username/web-honeypot.git
cd web-honeypot
pip install flask
python app.py
```

Visit: [http://localhost:5000](http://localhost:5000)

## 🔑 Admin Credentials

| Username | Password  |
|----------|-----------|
| admin    | password  |


## 🌐 Routes Summary

| Route         | Function                                   |
|---------------|--------------------------------------------|
| `/`           | Home page                                  |
| `/login`      | Simulated login (SQLi & brute-force trap)  |
| `/comment`    | Comment box (XSS trap)                     |
| `/admin-login`| Admin login                                |
| `/dashboard`  | Dashboard with logs & charts               |
| `/portal`     | Fake redirection portal (bait)             |
| `/blacklist`  | View & manage blocked IPs                  |


## ✍️ Sample Attack Test

Try injecting:
```sql
Username: ' OR 1=1 --
Password: anything
```

Or for XSS:
```html
<script>alert('XSS')</script>
```

These will get detected and logged, and IP gets blacklisted after 5 suspicious attempts.

## 📊 Tech Stack

- **Backend:** Flask (Python)
- **Frontend:** Bootstrap 5, Chart.js
- **Database:** SQLite
- **Session Security:** Flask session

## 🙋‍♂️ Author

**Nikhil Anand**  
