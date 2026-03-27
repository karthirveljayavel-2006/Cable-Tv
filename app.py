"""
Cable TV Customer Management System - Flask Backend
====================================================
Run: python app.py
API Base: http://localhost:5000/api
"""

import os
import hmac
import hashlib
import json
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import mysql.connector
from mysql.connector import pooling
import bcrypt
import jwt
import razorpay

# ──────────────────────────────────────────────
# App Configuration
# ──────────────────────────────────────────────
app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

# Change these values via environment variables in production
SECRET_KEY        = os.getenv("SECRET_KEY", "cabletv-super-secret-key-2024")
RAZORPAY_KEY_ID   = os.getenv("RAZORPAY_KEY_ID", "rzp_test_YOUR_KEY_ID")
RAZORPAY_SECRET   = os.getenv("RAZORPAY_SECRET", "YOUR_RAZORPAY_SECRET")
JWT_EXPIRY_HOURS  = 24

# ──────────────────────────────────────────────
# Database Configuration
# ──────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "user":     os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "cabletv_db"),
    "pool_size": 5,
    "pool_name": "cabletv_pool",
    "pool_reset_session": True,
}

def get_db():
    """Get a fresh database connection (simple, no pool for dev)."""
    cfg = {k: v for k, v in DB_CONFIG.items()
           if k not in ("pool_size", "pool_name", "pool_reset_session")}
    return mysql.connector.connect(**cfg)


def query(sql, params=None, fetch=True, lastrowid=False):
    """Execute SQL and return results."""
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    cur.execute(sql, params or ())
    if fetch:
        result = cur.fetchall()
        conn.close()
        return result
    conn.commit()
    rid = cur.lastrowid
    conn.close()
    return rid if lastrowid else True


# ──────────────────────────────────────────────
# JWT Helpers
# ──────────────────────────────────────────────
def create_token(user_id, is_admin=False):
    payload = {
        "user_id":  user_id,
        "is_admin": is_admin,
        "exp":      datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token):
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else None
        if not token:
            return jsonify({"error": "Token missing"}), 401
        try:
            data = decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        request.user = data
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if not request.user.get("is_admin"):
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


# ──────────────────────────────────────────────
# Database Initializer
# ──────────────────────────────────────────────
def init_db():
    """Run schema.sql and seed default data."""
    schema_path = os.path.join(os.path.dirname(__file__), "../database/schema.sql")
    with open(schema_path, "r") as f:
        sql = f.read()

    conn = get_db()
    cur  = conn.cursor()
    # Execute each statement
    for stmt in sql.split(";"):
        stmt = stmt.strip()
        if stmt and not stmt.startswith("--"):
            try:
                cur.execute(stmt)
            except Exception:
                pass
    conn.commit()
    conn.close()

    # Create default admin
    create_default_admin()
    create_sample_users()


def create_default_admin():
    existing = query("SELECT id FROM users WHERE is_admin=1 LIMIT 1")
    if existing:
        return
    hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
    query(
        "INSERT INTO users (name,phone,password,status,is_admin,stb_number) VALUES (%s,%s,%s,'Active',1,'ADM-0001')",
        ("Admin User", "9999999999", hashed),
        fetch=False,
    )
    print("✅ Default admin created → phone: 9999999999  password: admin123")


def create_sample_users():
    existing = query("SELECT id FROM users WHERE is_admin=0 LIMIT 1")
    if existing:
        return
    hashed = bcrypt.hashpw(b"password123", bcrypt.gensalt()).decode()
    samples = [
        ("Ravi Kumar",    "9876543210", hashed, 1, "Active",   "STB-1001"),
        ("Priya Sharma",  "9876543211", hashed, 3, "Active",   "STB-1002"),
        ("Amit Singh",    "9876543212", hashed, 2, "Inactive", "STB-1003"),
        ("Sunita Devi",   "9876543213", hashed, 5, "Active",   "STB-1004"),
        ("Raj Patel",     "9876543214", hashed, None, "Inactive", "STB-1005"),
    ]
    for s in samples:
        query(
            "INSERT INTO users (name,phone,password,plan_id,status,stb_number) VALUES (%s,%s,%s,%s,%s,%s)",
            s, fetch=False,
        )
    print("✅ Sample users created → password: password123")


# ──────────────────────────────────────────────
# AUTH ROUTES
# ──────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def login():
    data  = request.json or {}
    phone = data.get("phone", "").strip()
    pwd   = data.get("password", "")

    if not phone or not pwd:
        return jsonify({"error": "Phone and password required"}), 400

    rows = query("SELECT * FROM users WHERE phone=%s LIMIT 1", (phone,))
    if not rows:
        return jsonify({"error": "Invalid phone number or password"}), 401

    user = rows[0]
    if not bcrypt.checkpw(pwd.encode(), user["password"].encode()):
        return jsonify({"error": "Invalid phone number or password"}), 401

    token = create_token(user["id"], bool(user["is_admin"]))
    return jsonify({
        "token":    token,
        "is_admin": bool(user["is_admin"]),
        "user_id":  user["id"],
        "name":     user["name"],
    })


# ──────────────────────────────────────────────
# USER ROUTES
# ──────────────────────────────────────────────
@app.route("/api/user/profile", methods=["GET"])
@token_required
def get_profile():
    rows = query(
        """SELECT u.id, u.name, u.phone, u.status, u.stb_number, u.address,
                  p.id AS plan_id, p.name AS plan_name, p.price AS plan_price,
                  p.channels, p.duration_days
           FROM users u
           LEFT JOIN plans p ON u.plan_id = p.id
           WHERE u.id = %s""",
        (request.user["user_id"],),
    )
    if not rows:
        return jsonify({"error": "User not found"}), 404
    return jsonify(rows[0])


# ──────────────────────────────────────────────
# PLANS ROUTES
# ──────────────────────────────────────────────
@app.route("/api/plans", methods=["GET"])
@token_required
def get_plans():
    plans = query("SELECT * FROM plans WHERE is_active=1 ORDER BY price ASC")
    return jsonify(plans)


# ──────────────────────────────────────────────
# PAYMENT ROUTES (Razorpay)
# ──────────────────────────────────────────────
@app.route("/api/payment/create-order", methods=["POST"])
@token_required
def create_order():
    data    = request.json or {}
    plan_id = data.get("plan_id")
    if not plan_id:
        return jsonify({"error": "plan_id required"}), 400

    plans = query("SELECT * FROM plans WHERE id=%s AND is_active=1", (plan_id,))
    if not plans:
        return jsonify({"error": "Plan not found"}), 404

    plan   = plans[0]
    amount = int(float(plan["price"]) * 100)  # paise

    try:
        client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_SECRET))
        order  = client.order.create({
            "amount":   amount,
            "currency": "INR",
            "receipt":  f"rcpt_{request.user['user_id']}_{plan_id}",
        })
    except Exception as e:
        # Fallback for demo without real Razorpay keys
        order = {"id": f"order_demo_{plan_id}_{request.user['user_id']}"}

    # Record pending payment
    query(
        "INSERT INTO payments (user_id,plan_id,amount,razorpay_order_id,status) VALUES (%s,%s,%s,%s,'Pending')",
        (request.user["user_id"], plan_id, plan["price"], order["id"]),
        fetch=False,
    )

    return jsonify({
        "order_id":     order["id"],
        "amount":       amount,
        "currency":     "INR",
        "key_id":       RAZORPAY_KEY_ID,
        "plan_name":    plan["name"],
        "plan_price":   plan["price"],
    })


@app.route("/api/payment/verify", methods=["POST"])
@token_required
def verify_payment():
    data = request.json or {}
    razorpay_order_id   = data.get("razorpay_order_id")
    razorpay_payment_id = data.get("razorpay_payment_id")
    razorpay_signature  = data.get("razorpay_signature")
    plan_id             = data.get("plan_id")

    # Signature verification
    try:
        body = f"{razorpay_order_id}|{razorpay_payment_id}"
        expected = hmac.new(
            RAZORPAY_SECRET.encode(), body.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, razorpay_signature or ""):
            # Allow demo payments (no real signature)
            if not razorpay_order_id.startswith("order_demo_"):
                return jsonify({"error": "Payment verification failed"}), 400
    except Exception:
        pass

    # Update payment record
    query(
        """UPDATE payments SET razorpay_payment_id=%s, status='Success'
           WHERE razorpay_order_id=%s""",
        (razorpay_payment_id, razorpay_order_id),
        fetch=False,
    )

    # Update user plan & status
    query(
        "UPDATE users SET plan_id=%s, status='Active' WHERE id=%s",
        (plan_id, request.user["user_id"]),
        fetch=False,
    )

    return jsonify({"success": True, "message": "Payment successful! Plan activated."})


@app.route("/api/payment/demo-success", methods=["POST"])
@token_required
def demo_payment_success():
    """Simulate a successful payment without Razorpay (for demo/testing)."""
    data    = request.json or {}
    plan_id = data.get("plan_id")
    if not plan_id:
        return jsonify({"error": "plan_id required"}), 400

    plans = query("SELECT * FROM plans WHERE id=%s AND is_active=1", (plan_id,))
    if not plans:
        return jsonify({"error": "Plan not found"}), 404

    plan = plans[0]
    query(
        "INSERT INTO payments (user_id,plan_id,amount,razorpay_order_id,razorpay_payment_id,status) VALUES (%s,%s,%s,%s,%s,'Success')",
        (request.user["user_id"], plan_id, plan["price"],
         f"order_demo_{plan_id}", f"pay_demo_{plan_id}"),
        fetch=False,
    )
    query(
        "UPDATE users SET plan_id=%s, status='Active' WHERE id=%s",
        (plan_id, request.user["user_id"]),
        fetch=False,
    )
    return jsonify({"success": True, "message": f"Plan '{plan['name']}' activated successfully!"})


@app.route("/api/user/payment-history", methods=["GET"])
@token_required
def payment_history():
    rows = query(
        """SELECT pay.id, p.name AS plan_name, pay.amount, pay.status,
                  pay.payment_date, pay.razorpay_payment_id
           FROM payments pay
           JOIN plans p ON pay.plan_id = p.id
           WHERE pay.user_id = %s
           ORDER BY pay.payment_date DESC""",
        (request.user["user_id"],),
    )
    return jsonify(rows)


# ──────────────────────────────────────────────
# ADMIN ROUTES
# ──────────────────────────────────────────────
@app.route("/api/admin/customers", methods=["GET"])
@admin_required
def admin_get_customers():
    rows = query(
        """SELECT u.id, u.name, u.phone, u.status, u.stb_number,
                  u.address, u.created_at,
                  p.name AS plan_name, p.price AS plan_price
           FROM users u
           LEFT JOIN plans p ON u.plan_id = p.id
           WHERE u.is_admin = 0
           ORDER BY u.created_at DESC"""
    )
    return jsonify(rows)


@app.route("/api/admin/customers", methods=["POST"])
@admin_required
def admin_add_customer():
    d = request.json or {}
    required = ["name", "phone", "password"]
    for field in required:
        if not d.get(field):
            return jsonify({"error": f"{field} is required"}), 400

    # Check duplicate phone
    if query("SELECT id FROM users WHERE phone=%s", (d["phone"],)):
        return jsonify({"error": "Phone number already exists"}), 409

    hashed = bcrypt.hashpw(d["password"].encode(), bcrypt.gensalt()).decode()
    uid = query(
        "INSERT INTO users (name,phone,password,plan_id,status,stb_number,address) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (d["name"], d["phone"], hashed,
         d.get("plan_id") or None,
         d.get("status", "Inactive"),
         d.get("stb_number", ""),
         d.get("address", "")),
        fetch=False, lastrowid=True,
    )
    return jsonify({"success": True, "user_id": uid}), 201


@app.route("/api/admin/customers/<int:uid>", methods=["PUT"])
@admin_required
def admin_update_customer(uid):
    d = request.json or {}
    fields, vals = [], []

    for col in ("name", "phone", "status", "stb_number", "address"):
        if col in d:
            fields.append(f"{col}=%s")
            vals.append(d[col])
    if "plan_id" in d:
        fields.append("plan_id=%s")
        vals.append(d["plan_id"] or None)
    if "password" in d and d["password"]:
        fields.append("password=%s")
        vals.append(bcrypt.hashpw(d["password"].encode(), bcrypt.gensalt()).decode())

    if not fields:
        return jsonify({"error": "Nothing to update"}), 400

    vals.append(uid)
    query(f"UPDATE users SET {', '.join(fields)} WHERE id=%s AND is_admin=0",
          tuple(vals), fetch=False)
    return jsonify({"success": True})


@app.route("/api/admin/customers/<int:uid>", methods=["DELETE"])
@admin_required
def admin_delete_customer(uid):
    query("DELETE FROM users WHERE id=%s AND is_admin=0", (uid,), fetch=False)
    return jsonify({"success": True})


@app.route("/api/admin/payments", methods=["GET"])
@admin_required
def admin_payments():
    rows = query(
        """SELECT pay.id, u.name AS user_name, u.phone,
                  p.name AS plan_name, pay.amount, pay.status,
                  pay.payment_date, pay.razorpay_payment_id
           FROM payments pay
           JOIN users u ON pay.user_id = u.id
           JOIN plans  p ON pay.plan_id = p.id
           ORDER BY pay.payment_date DESC
           LIMIT 200"""
    )
    return jsonify(rows)


@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def admin_stats():
    total    = query("SELECT COUNT(*) AS c FROM users WHERE is_admin=0")[0]["c"]
    active   = query("SELECT COUNT(*) AS c FROM users WHERE is_admin=0 AND status='Active'")[0]["c"]
    revenue  = query("SELECT IFNULL(SUM(amount),0) AS r FROM payments WHERE status='Success'")[0]["r"]
    payments = query("SELECT COUNT(*) AS c FROM payments WHERE status='Success'")[0]["c"]
    return jsonify({
        "total_customers": total,
        "active_customers": active,
        "inactive_customers": total - active,
        "total_revenue": float(revenue),
        "total_payments": payments,
    })


# ──────────────────────────────────────────────
# Serve Frontend
# ──────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("../frontend/pages", "login.html")

@app.route("/<path:path>")
def serve_frontend(path):
    if os.path.exists(os.path.join("../frontend", path)):
        return send_from_directory("../frontend", path)
    return send_from_directory("../frontend/pages", "login.html")


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("🚀 Initializing Cable TV CMS Backend...")
    init_db()
    print("🌐 Server running at http://localhost:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
