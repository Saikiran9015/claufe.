from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, send_from_directory, jsonify
)
import os
import datetime
import requests
import razorpay
import hmac
import hashlib
import json

from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson.objectid import ObjectId

# =====================================================
# LOAD .env
# =====================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

# =====================================================
# CONFIG
# =====================================================
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change_this_secret_key")

RAZORPAY_KEY = os.getenv("RAZORPAY_KEY")
RAZORPAY_SECRET = os.getenv("RAZORPAY_SECRET")
MONGO_URL = os.getenv("MONGODB_URI")

# Razorpay Client
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY, RAZORPAY_SECRET))

# =====================================================
# MONGO DB
# =====================================================
mongo = MongoClient(MONGO_URL)
db = mongo["dreamx"]

users_col = db["users"]
cart_col = db["cart"]
orders_col = db["orders"]
products_col = db["products"]
banners_col = db["banners"]

# =====================================================
# UPLOAD SETTINGS
# =====================================================
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_EXT = {"png", "jpg", "jpeg", "webp"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


# =====================================================
# CREATE DEFAULT USERS
# =====================================================
def init_mongo():
    if not users_col.find_one({"email": "admin@claufe.com"}):
        users_col.insert_one({
            "name": "Admin",
            "email": "admin@claufe.com",
            "password_hash": generate_password_hash("admin123"),
            "role": "admin",
            "created_at": datetime.datetime.now()
        })

    if not users_col.find_one({"email": "user@claufe.com"}):
        users_col.insert_one({
            "name": "Regular User",
            "email": "user@claufe.com",
            "password_hash": generate_password_hash("user123"),
            "role": "user",
            "created_at": datetime.datetime.now()
        })


init_mongo()

# =====================================================
# AUTH HELPERS
# =====================================================
def require_login():
    if "user_id" not in session:
        flash("Please log in first!", "error")
        return redirect(url_for("login"))
    return None


def require_admin():
    need = require_login()
    if need:
        return need
    if session.get("role") != "admin":
        flash("Admin access only!", "error")
        return redirect(url_for("landing"))
    return None


# =====================================================
# PUBLIC LANDING PAGE
# =====================================================
@app.route("/")
def landing():
    products = list(products_col.find().sort("created_at", -1))
    banners = list(banners_col.find().sort("created_at", -1))
    return render_template("landing.html", products=products, banners=banners)


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# =====================================================
# PRODUCT DETAILS
# =====================================================
@app.route("/product/<string:product_id>")
def product_page(product_id):
    try:
        obj_id = ObjectId(product_id)
    except:
        flash("Invalid product!", "error")
        return redirect(url_for("landing"))

    product = products_col.find_one({"_id": obj_id})
    if not product:
        flash("Product not found!", "error")
        return redirect(url_for("landing"))

    images = product.get("images")
    if not images:
        images = [product.get("image_filename")] if product.get("image_filename") else []

    product["images"] = images

    return render_template(
        "product_page.html",
        p=product,
        size_order=["S", "M", "L", "XL", "XXL"]
    )


# =====================================================
# SIGNUP
# =====================================================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email").lower()
        password = request.form.get("password")

        if users_col.find_one({"email": email}):
            flash("Email already exists!", "error")
            return redirect(url_for("signup"))

        users_col.insert_one({
            "name": name,
            "email": email,
            "password_hash": generate_password_hash(password),
            "role": "user",
            "created_at": datetime.datetime.now()
        })

        flash("Signup success!", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


# =====================================================
# LOGIN / LOGOUT
# =====================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email").lower()
        password = request.form.get("password")

        user = users_col.find_one({"email": email})
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid login!", "error")
            return redirect(url_for("login"))

        session["user_id"] = str(user["_id"])
        session["email"] = user["email"]
        session["name"] = user["name"]
        session["role"] = user["role"]

        return redirect(
            url_for("admin_dashboard") if user["role"] == "admin" else url_for("landing")
        )

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out!", "success")
    return redirect(url_for("landing"))


# =====================================================
# CART
# =====================================================
# =====================================================
# ADD TO CART (DYNAMIC SIZE PRICE)
# =====================================================
@app.route("/add-to-cart/<string:product_id>", methods=["GET", "POST"])
def add_to_cart(product_id):
    need = require_login()
    if need:
        return need

    try:
        product = products_col.find_one({"_id": ObjectId(product_id)})
    except:
        flash("Invalid product!", "error")
        return redirect(url_for("landing"))

    # selected size
    if request.method == "POST":
        size = request.form.get("size", "M")
        qty = int(request.form.get("qty", 1))
    else:
        size = request.args.get("size", "M")
        qty = int(request.args.get("qty", 1))

    # choose correct price per size
    selected_price = product.get("prices", {}).get(size, product["price"])

    cart_col.insert_one({
        "user_email": session["email"],
        "product_id": product["_id"],
        "name": product["name"],
        "price": float(selected_price),    # <--- IMPORTANT
        "image": product.get("image_filename"),
        "size": size,
        "quantity": qty,
        "added_at": datetime.datetime.now()
    })

    flash("Added to cart!", "success")
    return redirect(url_for("cart"))

@app.route("/cart")
def cart():
    need = require_login()
    if need:
        return need

    items = list(cart_col.find({"user_email": session["email"]}))
    total = sum(float(i["price"]) * i["quantity"] for i in items)

    return render_template("cart.html", items=items, total=total)


@app.route("/cart/update/<string:item_id>", methods=["POST"])
def update_cart_item(item_id):
    need = require_login()
    if need:
        return need

    size = request.form.get("size", "M")
    qty_raw = request.form.get("quantity", "1")
    try:
        qty = int(qty_raw)
    except ValueError:
        qty = 1
    if qty < 1:
        qty = 1

    cart_col.update_one({"_id": ObjectId(item_id)}, {"$set": {"size": size, "quantity": qty}})
    flash("Cart updated!", "success")
    return redirect(url_for("cart"))


@app.route("/cart/delete/<string:item_id>", methods=["POST"])
def delete_cart_item(item_id):
    need = require_login()
    if need:
        return need

    cart_col.delete_one({"_id": ObjectId(item_id)})
    flash("Item removed!", "success")
    return redirect(url_for("cart"))

#====================================================
#RATINGS AND REVIEWS
#====================================================
@app.route("/admin/update-rating/<string:product_id>", methods=["POST"])
def update_rating(product_id):
    need = require_admin()
    if need:
        return need

    rating = float(request.form.get("rating", 0))
    if rating < 0 or rating > 5:
        flash("Rating must be between 0 and 5!", "error")
        return redirect(url_for("product_page", product_id=product_id))

    products_col.update_one(
        {"_id": ObjectId(product_id)},
        {"$set": {"rating": rating}}
    )

    flash("Rating updated!", "success")
    return redirect(url_for("product_page", product_id=product_id))

# =====================================================
# CHECKOUT (WITH ADDRESS SAVE)
# =====================================================
# =====================================================
# CHECKOUT (WITH ADDRESS SAVE)
# =====================================================
@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    need = require_login()
    if need:
        return need

    items = list(cart_col.find({"user_email": session["email"]}))
    if not items:
        flash("Your cart is empty!", "error")
        return redirect(url_for("cart"))

    total = sum(float(i["price"]) * i["quantity"] for i in items)

    if request.method == "POST":
        # normalize to address1/address2 keys used by shiprocket_create_order
        session["checkout_address"] = {
            "full_name": request.form.get("full_name"),
            "phone": request.form.get("phone"),
            "email": session["email"],
            "address1": request.form.get("address"),
            "address2": request.form.get("address2"),
            "city": request.form.get("city"),
            "state": request.form.get("state"),
            "pincode": request.form.get("pincode")
        }
        return redirect(url_for("checkout"))

    return render_template(
        "checkout.html",
        items=items,
        total=total,
        razorpay_key=RAZORPAY_KEY
    )


# =====================================================
# CREATE RAZORPAY ORDER
# =====================================================
@app.route("/create-razorpay-order", methods=["POST"])
def create_razorpay_order():
    data = request.get_json() or {}
    # checkout.html already sends amount in paise (TOTAL_AMOUNT = total * 100)
    amount_paise = int(data.get("amount", 0))
    order = razorpay_client.order.create({
        "amount": amount_paise,
        "currency": "INR",
        "payment_capture": 1
    })
    return jsonify(order)

@app.route("/save-address", methods=["POST"])
def save_address():
    data = request.get_json()

    session["checkout_address"] = {
        "full_name": data.get("full_name"),
        "phone": data.get("phone"),
        "email": data.get("email"),
        "address1": data.get("address1"),
        "address2": data.get("address2"),
        "city": data.get("city"),
        "state": data.get("state"),
        "pincode": data.get("pincode")
    }
    return jsonify({"saved": True})


# =====================================================
# SHIPROCKET CONFIG / HELPERS
SHIPROCKET_BASE_URL = "https://apiv2.shiprocket.in/v1/external"
SHIPROCKET_EMAIL = os.getenv("SHIPROCKET_EMAIL")
SHIPROCKET_PASSWORD = os.getenv("SHIPROCKET_PASSWORD")


def shiprocket_login():
    url = f"{SHIPROCKET_BASE_URL}/auth/login"
    data = {
        "email": SHIPROCKET_EMAIL,
        "password": SHIPROCKET_PASSWORD,
    }
    try:
        r = requests.post(url, json=data)
        print(f"Shiprocket Login Status: {r.status_code}")
        print(f"Shiprocket Login Response: {r.text}")
        r.raise_for_status()
        return r.json().get("token")
    except Exception as e:
        print(f"Shiprocket Login Error: {e}")
        raise



def shiprocket_create_order(order, address):
    token = shiprocket_login()

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # be tolerant with address keys (address vs address1)
    addr1 = address.get("address1") or address.get("address") or ""
    addr2 = address.get("address2") or ""

    payload = {
        "order_id": str(order["_id"]),
        "order_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "pickup_location": "Primary",

        "billing_customer_name": address.get("full_name", ""),
        "billing_last_name": "",
        "billing_address": addr1,
        "billing_address_2": addr2,
        "billing_city": address.get("city", ""),
        "billing_pincode": address.get("pincode", "") or address.get("pin", ""),
        "billing_state": address.get("state", ""),
        "billing_country": "India",
        "billing_email": address.get("email", ""),
        "billing_phone": address.get("phone", ""),
        "shipping_is_billing": True,

        "order_items": [
            {
                "name": str(i["name"]),
                "sku": str(i["product_id"]),
                "units": int(i["quantity"]),
                "selling_price": float(i["price"])
            }
            for i in order["items"]
        ],

        "payment_method": "Prepaid",
        "sub_total": float(order["total"]),

        # Simple default dimensions
        "length": 10,
        "breadth": 10,
        "height": 10,
        "weight": 0.5
    }

    url = f"{SHIPROCKET_BASE_URL}/orders/create/adhoc"
    r = requests.post(url, json=payload, headers=headers)
    r.raise_for_status()
    return r.json()


# =====================================================
# VERIFY PAYMENT + SAVE ORDER + CREATE SHIPROCKET ORDER
# =====================================================
@app.route("/verify-payment", methods=["POST"])
def verify_payment():
    data = request.get_json()

    payment_id = data.get("razorpay_payment_id")
    order_id = data.get("razorpay_order_id")
    signature = data.get("razorpay_signature")

    message = f"{order_id}|{payment_id}"
    generated_signature = hmac.new(
        bytes(RAZORPAY_SECRET, 'utf-8'),
        bytes(message, 'utf-8'),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(generated_signature, signature):
        return jsonify({"success": False, "redirect_url": FAILED_URL})

    # CART
    items = list(cart_col.find({"user_email": session["email"]}))
    total = sum(float(i["price"]) * i["quantity"] for i in items)

    # ADDRESS SAVED BEFORE PAYMENT
    address = session.get("checkout_address", {})

    # SAVE ORDER
    new_order_id = orders_col.insert_one({
        "user_email": session["email"],
        "items": items,
        "total": total,
        "status": "Paid",
        "payment_id": payment_id,
        "order_id": order_id,
        "payment_method": "Prepaid",
        "address": address,
        "created_at": datetime.datetime.now()
    }).inserted_id

    order_doc = orders_col.find_one({"_id": new_order_id})

    # CREATE SHIPROCKET ORDER
    try:
        ship_data = shiprocket_create_order(order_doc, address)
        orders_col.update_one(
            {"_id": new_order_id},
            {"$set": {
                "shiprocket_order_id": ship_data.get("order_id"),
                "shiprocket_shipment_id": ship_data.get("shipment_id"),
                "shiprocket_status": ship_data.get("status"),
                "shiprocket_response": ship_data
            }}
        )
    except Exception as e:
        print("Shiprocket Error:", e)
        # record error on order for debugging
        orders_col.update_one({"_id": new_order_id}, {"$set": {"shiprocket_error": str(e)}})

    cart_col.delete_many({"user_email": session["email"]})

    # After successful verification and order save, redirect user to landing page
    return jsonify({"success": True, "redirect_url": url_for("landing")})


# Razorpay webhook endpoint
@app.route("/razorpay-webhook", methods=["POST"])
def razorpay_webhook():
    print("\n=== Webhook Received ===")
    print("Headers:", dict(request.headers))
    print("Raw data:", request.get_data().decode('utf-8'))
    
    payload = request.get_data()
    signature = request.headers.get("X-Razorpay-Signature", "")
    print("Signature from header:", signature)
    # verify signature
    try:
        generated_sig = hmac.new(
            bytes(RAZORPAY_SECRET, "utf-8"),
            payload,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(generated_sig, signature):
            return jsonify({"status": "invalid_signature"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

    data = request.get_json(silent=True) or {}
    event = data.get("event", "")

    # handle relevant events
    try:
        if event == "payment.captured" or event == "order.paid":
            payment_entity = (
                data.get("payload", {})
                    .get("payment", {})
                    .get("entity", {})
            )
            payment_id = payment_entity.get("id")
            razor_order_id = payment_entity.get("order_id")

            # update by payment_id first, fallback to razorpay order_id
            if payment_id:
                orders_col.update_one({"payment_id": payment_id}, {"$set": {"status": "Paid"}})
            if razor_order_id:
                orders_col.update_one({"order_id": razor_order_id}, {"$set": {"status": "Paid"}})

        elif event == "payment.failed":
            payment_entity = (
                data.get("payload", {})
                    .get("payment", {})
                    .get("entity", {})
            )
            payment_id = payment_entity.get("id")
            razor_order_id = payment_entity.get("order_id")

            if payment_id:
                orders_col.update_one({"payment_id": payment_id}, {"$set": {"status": "Failed"}})
            if razor_order_id:
                orders_col.update_one({"order_id": razor_order_id}, {"$set": {"status": "Failed"}})

        # Add more event handling as needed

    except Exception as e:
        # don't expose internals to Razorpay, but log for debugging
        print("Webhook processing error:", e)

    return jsonify({"status": "ok"})


# =====================================================
# ORDER SUCCESS
# =====================================================
@app.route("/order-success")
def order_success():
    need = require_login()
    if need:
        return need

    # Fetch last order for this user
    order = orders_col.find_one(
        {"user_email": session["email"]},
        sort=[("created_at", -1)]
    )

    return render_template("order_success.html", order=order)


# =====================================================
# ADMIN — BANNERS
# =====================================================
@app.route("/admin/banners", methods=["GET", "POST"])
def admin_banners():
    need = require_admin()
    if need:
        return need

    if request.method == "POST":
        file = request.files.get("image")

        if file and allowed_file(file.filename):
            filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + "_" + secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

            banners_col.insert_one({
                "image_filename": filename,
                "created_at": datetime.datetime.now()
            })

            flash("Banner uploaded!", "success")
            return redirect(url_for("admin_banners"))

    banners = list(banners_col.find().sort("created_at", -1))
    return render_template("admin_banners.html", banners=banners)


@app.route("/admin/banner/delete/<string:banner_id>", methods=["POST"])
def delete_banner(banner_id):
    need = require_admin()
    if need:
        return need

    banner = banners_col.find_one({"_id": ObjectId(banner_id)})
    if banner:
        try:
            os.remove(os.path.join(app.config["UPLOAD_FOLDER"], banner["image_filename"]))
        except Exception:
            pass
        banners_col.delete_one({"_id": ObjectId(banner_id)})

    flash("Banner deleted!", "success")
    return redirect(url_for("admin_banners"))


# =====================================================
# ADMIN — DASHBOARD
# =====================================================
@app.route("/admin/dashboard")
def admin_dashboard():
    need = require_admin()
    if need:
        return need

    total_products = products_col.count_documents({})

    rev = list(products_col.aggregate([
        {"$group": {"_id": None, "total": {"$sum": "$price"}}}
    ]))
    total_revenue = float(rev[0]["total"]) if rev else 0

    latest = list(products_col.find().sort("created_at", -1).limit(5))

    return render_template(
        "dashboard.html",
        total_products=total_products,
        total_revenue=total_revenue,
        latest_products=latest,
        active_page="dashboard"
    )


# =====================================================
# ADMIN — PRODUCTS LIST
# =====================================================
@app.route("/admin/products")
def admin_products():
    need = require_admin()
    if need:
        return need

    products = list(products_col.find().sort("created_at", -1))
    return render_template("products.html", products=products, active_page="products")


# =====================================================
# ADMIN — ADD PRODUCT
# =====================================================
@app.route("/admin/products/add", methods=["GET", "POST"])
def add_product():
    need = require_admin()
    if need:
        return need

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price = request.form.get("price", "").strip()
        old_price = request.form.get("old_price", "").strip()
        description = request.form.get("description", "").strip()
        selected_sizes = request.form.getlist("sizes")

        # ⭐️ Rating added
        rating_raw = request.form.get("rating")
        try:
            rating = float(rating_raw)
        except:
            rating = None

        # stock per size
        stock = {}
        for s in ["S", "M", "L", "XL", "XXL"]:
            qty_str = request.form.get(f"stock_{s}", "0")
            try:
                qty = int(qty_str)
            except ValueError:
                qty = 0
            if s in selected_sizes and qty > 0:
                stock[s] = qty

        image_files = request.files.getlist("images")
        saved_images = []

        for file in image_files[:4]:
            if file and allowed_file(file.filename):
                filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + "_" + secure_filename(file.filename)
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                saved_images.append(filename)

        if not saved_images:
            flash("Upload at least one image", "error")
            return redirect(url_for("add_product"))

        main_image = saved_images[0]

        # insert DB
        products_col.insert_one({
            "name": name,
            "description": description,
            "price": float(price),
            "old_price": float(old_price) if old_price else None,
            "image_filename": main_image,
            "images": saved_images,
            "sizes": selected_sizes,
            "stock": stock,
            "rating": rating,     # ⭐️ Stored Here
            "created_at": datetime.datetime.now()
        })

        flash("Product added!", "success")
        return redirect(url_for("admin_products"))

    return render_template("upload.html", active_page="upload")
#====================================================


# =====================================================
# ADMIN — DELETE PRODUCT
# =====================================================
@app.route("/admin/products/delete/<string:product_id>", methods=["POST"])
def delete_product(product_id):
    need = require_admin()
    if need:
        return need

    product = products_col.find_one({"_id": ObjectId(product_id)})
    if product:
        try:
            if product.get("image_filename"):
                os.remove(os.path.join(app.config["UPLOAD_FOLDER"], product["image_filename"]))
        except Exception:
            pass
        products_col.delete_one({"_id": ObjectId(product_id)})

    flash("Deleted!", "success")
    return redirect(url_for("admin_products"))


# =====================================================
# ADMIN — ANALYTICS
# =====================================================
@app.route("/admin/analytics")
def admin_analytics():
    need = require_admin()
    if need:
        return need

    total_products = products_col.count_documents({})

    rev = list(products_col.aggregate([
        {"$group": {"_id": None, "sum": {"$sum": "$price"}}}
    ]))
    total_revenue = float(rev[0]["sum"]) if rev else 0

    avg = list(products_col.aggregate([
        {"$group": {"_id": None, "avg": {"$avg": "$price"}}}
    ]))
    avg_price = float(avg[0]["avg"]) if avg else 0

    return render_template(
        "analytics.html",
        total_products=total_products,
        total_revenue=total_revenue,
        avg_price=avg_price,
        active_page="analytics"
    )


# =====================================================
# RUN SERVER
# =====================================================
if __name__ == "__main__":
    app.run(debug=True)
