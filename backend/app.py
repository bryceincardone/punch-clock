from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__, static_folder='frontend', static_url_path='')
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_new.db'

CORS(app, supports_credentials=True)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

# -------------------- MODELS --------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class TimeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.String(100), nullable=False)
    job_name = db.Column(db.String(150))

# -------------------- INIT DB --------------------
with app.app_context():
    db.create_all()
    existing_admin = User.query.filter_by(username='BryceIncardone').first()
    if not existing_admin:
        admin_user = User(username='BryceIncardone', password=generate_password_hash('Password'), is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
    elif not existing_admin.is_admin:
        existing_admin.is_admin = True
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- AUTH ROUTES --------------------
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']
    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists"}), 400
    hashed_pw = generate_password_hash(password)
    new_user = User(username=username, password=hashed_pw, is_admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid credentials"}), 401
    login_user(user)
    return jsonify({"message": "Login successful", "username": user.username, "is_admin": user.is_admin}), 200

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/whoami', methods=['GET'])
@login_required
def whoami():
    return jsonify({"username": current_user.username, "is_admin": current_user.is_admin}), 200

# -------------------- CLOCK IN/OUT --------------------
@app.route('/clockin', methods=['POST'])
@login_required
def clock_in():
    last_log = TimeLog.query.filter_by(user_id=current_user.id).order_by(TimeLog.timestamp.desc()).first()
    if last_log and last_log.action == 'clockin':
        return jsonify({"message": "You are already clocked in."}), 400
    data = request.get_json()
    job_name = data.get('job_name', '')
    now = datetime.now().isoformat()
    log = TimeLog(user_id=current_user.id, action="clockin", timestamp=now, job_name=job_name)
    db.session.add(log)
    db.session.commit()
    return jsonify({"message": f"{current_user.username} clocked in at {now}"}), 200

@app.route('/clockout', methods=['POST'])
@login_required
def clock_out():
    last_log = TimeLog.query.filter_by(user_id=current_user.id).order_by(TimeLog.timestamp.desc()).first()
    if not last_log or last_log.action != 'clockin':
        return jsonify({"message": "You must be clocked in to clock out."}), 400
    now = datetime.now().isoformat()
    log = TimeLog(user_id=current_user.id, action="clockout", timestamp=now, job_name=last_log.job_name)
    db.session.add(log)
    db.session.commit()
    return jsonify({"message": f"{current_user.username} clocked out at {now}"}), 200

# -------------------- EXPORT PAYROLL --------------------
@app.route('/admin_export_csv', methods=['GET'])
@login_required
def admin_export_csv():
    if not current_user.is_admin:
        return jsonify({"message": "Unauthorized"}), 403
    start = request.args.get('start')
    end = request.args.get('end')
    start_dt = datetime.strptime(start, "%Y-%m-%d") if start else None
    end_dt = datetime.strptime(end, "%Y-%m-%d") if end else None
    logs = TimeLog.query.order_by(TimeLog.timestamp).all()
    totals = defaultdict(float)
    for log in logs:
        ts = datetime.fromisoformat(log.timestamp)
        if start_dt and ts < start_dt: continue
        if end_dt and ts > end_dt: continue
        if log.action == 'clockin':
            clockin = ts
            next_log = TimeLog.query.filter(TimeLog.user_id == log.user_id, TimeLog.timestamp > log.timestamp).order_by(TimeLog.timestamp).first()
            if next_log and next_log.action == 'clockout':
                clockout = datetime.fromisoformat(next_log.timestamp)
                hours = (clockout - clockin).total_seconds() / 3600.0
                totals[log.user_id] += hours
    output = [["Username", "Pay Period Start", "Pay Period End", "Total Hours"]]
    for uid, hours in totals.items():
        user = User.query.get(uid)
        output.append([user.username, start, end, f"{hours:.2f}"])
    csv = '\n'.join([','.join(map(str, row)) for row in output])
    return Response(csv, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=payroll_logs.csv"})

# -------------------- EXPORT JOB SUMMARY --------------------
@app.route('/admin_export_job_summary', methods=['GET'])
@login_required
def export_job_summary():
    if not current_user.is_admin:
        return jsonify({"message": "Unauthorized"}), 403
    logs = TimeLog.query.order_by(TimeLog.timestamp).all()
    job_data = defaultdict(lambda: defaultdict(float))
    for log in logs:
        if log.action != 'clockin': continue
        clockin = datetime.fromisoformat(log.timestamp)
        next_log = TimeLog.query.filter(TimeLog.user_id == log.user_id, TimeLog.timestamp > log.timestamp).order_by(TimeLog.timestamp).first()
        if next_log and next_log.action == 'clockout':
            clockout = datetime.fromisoformat(next_log.timestamp)
            hours = (clockout - clockin).total_seconds() / 3600.0
            job_data[log.job_name][log.user_id] += hours
    output = [["Job Name", "Employee", "Total Hours"]]
    for job, users in job_data.items():
        for uid, hours in users.items():
            user = User.query.get(uid)
            output.append([job or "Unspecified", user.username, f"{hours:.2f}"])
    if len(output) == 1:
        output.append(["No data", "", ""])
    csv = '\n'.join([','.join(map(str, row)) for row in output])
    return Response(csv, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=job_hours_summary.csv"})

# -------------------- EXPORT FILTERED LOGS --------------------
@app.route('/admin_logs_export_csv', methods=['GET'])
@login_required
def export_filtered_logs():
    if not current_user.is_admin:
        return jsonify({"message": "Unauthorized"}), 403
    start = request.args.get('start')
    end = request.args.get('end')
    start_dt = datetime.strptime(start, "%Y-%m-%d") if start else None
    end_dt = datetime.strptime(end, "%Y-%m-%d") if end else None
    logs = TimeLog.query.order_by(TimeLog.timestamp).all()
    output = [["Username", "Action", "Timestamp", "Job Name"]]
    for log in logs:
        ts = datetime.fromisoformat(log.timestamp)
        if start_dt and ts < start_dt: continue
        if end_dt and ts > end_dt: continue
        user = User.query.get(log.user_id)
        output.append([user.username, log.action, log.timestamp, log.job_name or ""])
    csv = '\n'.join([','.join(map(str, row)) for row in output])
    return Response(csv, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=filtered_logs.csv"})

# -------------------- ADMIN ROUTES --------------------
@app.route('/admin_users', methods=['GET'])
@login_required
def admin_users():
    if not current_user.is_admin:
        return jsonify({"message": "Unauthorized"}), 403
    users = User.query.all()
    return jsonify([{"id": u.id, "username": u.username, "is_admin": u.is_admin} for u in users])

@app.route('/admin_logs', methods=['GET'])
@login_required
def admin_logs():
    if not current_user.is_admin:
        return jsonify({"message": "Unauthorized"}), 403
    start = request.args.get('start')
    end = request.args.get('end')
    start_dt = datetime.strptime(start, "%Y-%m-%d") if start else None
    end_dt = datetime.strptime(end, "%Y-%m-%d") if end else None
    logs = TimeLog.query.order_by(TimeLog.timestamp).all()
    data = []
    for log in logs:
        ts = datetime.fromisoformat(log.timestamp)
        if start_dt and ts.date() < start_dt.date(): continue
        if end_dt and ts.date() > end_dt.date(): continue
        user = User.query.get(log.user_id)
        data.append({"log_id": log.id, "username": user.username, "action": log.action, "timestamp": log.timestamp, "job_name": log.job_name})
    return jsonify(data)

@app.route('/admin_edit_log', methods=['PATCH'])
@login_required
def admin_edit_log():
    if not current_user.is_admin:
        return jsonify({"message": "Unauthorized"}), 403
    data = request.get_json()
    log = TimeLog.query.get(data['log_id'])
    if 'timestamp' in data:
        log.timestamp = data['timestamp']
    if 'job_name' in data:
        log.job_name = data['job_name']
    db.session.commit()
    return jsonify({"message": "Log updated successfully"})

@app.route('/admin_delete_log/<int:log_id>', methods=['DELETE'])
@login_required
def admin_delete_log(log_id):
    if not current_user.is_admin:
        return jsonify({"message": "Unauthorized"}), 403
    log = TimeLog.query.get(log_id)
    db.session.delete(log)
    db.session.commit()
    return jsonify({"message": "Log deleted successfully"})

@app.route('/admin_delete_user/<int:user_id>', methods=['DELETE'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({"message": "Unauthorized"}), 403
    if current_user.id == user_id:
        return jsonify({"message": "You cannot delete yourself."}), 400
    user = User.query.get(user_id)
    TimeLog.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted"})

@app.route('/admin_toggle_admin/<int:user_id>', methods=['PATCH'])
@login_required
def admin_toggle_admin(user_id):
    if not current_user.is_admin:
        return jsonify({"message": "Unauthorized"}), 403
    user = User.query.get(user_id)
    if current_user.id == user.id:
        return jsonify({"message": "Cannot toggle yourself"}), 400
    user.is_admin = not user.is_admin
    db.session.commit()
    return jsonify({"message": "Admin status updated"})

# -------------------- RUN --------------------
@app.route('/')
def home():
    return app.send_static_file('login.html')

if __name__ == '__main__':
    print("🚀 Flask server is running with full export and admin features...")
    app.run(debug=True)
