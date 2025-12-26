from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, send_from_directory, jsonify, Response
)
import os
import datetime
import requests
import razorpay
import time
from io import BytesIO
from PIL import Image
import hmac
import hashlib
import json
import base64
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from gridfs import GridFS
from bson.objectid import ObjectId

# Optional S3 fallback for read-only filesystems
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except Exception:
    boto3 = None
    BotoCoreError = Exception
    ClientError = Exception

# =====================================================
# LOAD .env
# =====================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

# =====================================================
# CONFIG
# =====================================================
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv(
    "SECRET_KEY",
    "claufe_production_secret_key_2025"
)

# Make cookie security configurable so local (HTTP) development still works.
# In production set `SESSION_COOKIE_SECURE=True` and `SESSION_COOKIE_SAMESITE=None`
# in your environment/.env. For local development over HTTP we default to safer
# values that allow the browser to receive session cookies.
# Default SameSite to Lax for normal behavior unless overridden by env.
session_cookie_samesite = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
# If the user explicitly sets SESSION_COOKIE_SECURE in env, respect it.
if "SESSION_COOKIE_SECURE" in os.environ:
    session_cookie_secure = os.getenv("SESSION_COOKIE_SECURE", "False").lower() in ("1", "true", "yes")
else:
    # Do not enable `Secure` by default so local HTTP development works.
    session_cookie_secure = False

app.config.update(
    SESSION_COOKIE_SAMESITE=session_cookie_samesite,
    SESSION_COOKIE_SECURE=session_cookie_secure,
    SESSION_COOKIE_HTTPONLY=True
)

print(f"Session cookie config: SameSite={session_cookie_samesite}, Secure={session_cookie_secure}")

# When true, skip DB/GridFS writes and persist banners to local filesystem only.
# Useful for live servers that cannot reach MongoDB temporarily.
FORCE_LOCAL_STORAGE = os.getenv("FORCE_LOCAL_STORAGE", "False").lower() in ("1", "true", "yes")
if FORCE_LOCAL_STORAGE:
    print("FORCE_LOCAL_STORAGE enabled: banners will be saved locally only")

# Limit uploads to ~6MB (slightly above the 5MB image target)
app.config['MAX_CONTENT_LENGTH'] = 6 * 1024 * 1024


RAZORPAY_KEY = os.getenv("RAZORPAY_KEY")
RAZORPAY_SECRET = os.getenv("RAZORPAY_SECRET")
MONGO_URL = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
SUCCESS_URL = os.getenv("SUCCESS_URL", "/order-success")
FAILED_URL = os.getenv("FAILED_URL", "/checkout")

# Razorpay Client
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY, RAZORPAY_SECRET))
#################################################################################################################################
# =====================================================
# MONGO DB (env-driven)
# =====================================================
# Allow setting DB name via env; default to previous value for compatibility
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "dreamx")

# Connection options that can be tuned via env
MONGO_TIMEOUT_MS = int(os.getenv("MONGO_TIMEOUT_MS", "5000"))
# For mongodb+srv URIs, PyMongo will use TLS by default; allow override via env
MONGO_TLS = os.getenv("MONGO_TLS", "auto").lower()  # auto/true/false

# Build MongoClient kwargs depending on URI and env
client_kwargs = {"serverSelectionTimeoutMS": MONGO_TIMEOUT_MS}
if MONGO_URL.startswith("mongodb+srv://"):
    if MONGO_TLS == "true":
        client_kwargs["tls"] = True
    elif MONGO_TLS == "false":
        client_kwargs["tls"] = False
    # if MONGO_TLS == 'auto', leave PyMongo defaults (it will enable TLS)

# Create client with a server selection timeout so startup can detect
# connectivity issues quickly. If ping fails we keep a client but mark
# `DB_CONNECTED=False` so the app can still run without DB (uploads still save locally).
try:
    mongo = MongoClient(MONGO_URL, **client_kwargs)
    # quick ping to confirm connectivity
    mongo.admin.command('ping')
    DB_CONNECTED = True
    # Print masked host for diagnostics without leaking credentials
    try:
        host_display = MONGO_URL.split('@')[-1]
    except Exception:
        host_display = MONGO_URL
    print(f"MongoDB connected to: {host_display} , DB: {MONGO_DB_NAME}")
except Exception as e:
    print("Warning: Could not connect to MongoDB at", MONGO_URL, ":", e)
    # keep a client instance (lazy) but mark disconnected so code can conditionally
    # perform initialization tasks only when DB is healthy.
    try:
        mongo = MongoClient(MONGO_URL, **client_kwargs)
    except Exception:
        # last-resort: create a default local client (will still likely fail operations)
        mongo = MongoClient("mongodb://localhost:27017/")
    DB_CONNECTED = False
#####################################################################################################################
db = mongo[MONGO_DB_NAME]
# GridFS for storing larger binary files in MongoDB
fs = GridFS(db)


users_col = db["users"]
cart_col = db["cart"]
orders_col = db["orders"]
products_col = db["products"]
banners_col = db[os.getenv("BANNERS_COLLECTION", "banners")]
print(f"Using MongoDB collection for banners: {banners_col.name}")
addresses_col = db["addresses"]
social_col = db["social_links"]
@app.context_processor
def inject_social():
    try:
        social = social_col.find_one() or {}

        links = {
            "instagram": social.get("instagram_url"),
            "facebook": social.get("facebook_url"),
            "twitter": social.get("twitter_url"),
            "youtube": social.get("youtube_url")
        }

        def to_public(src):
            if not src:
                return None
            if isinstance(src, str) and (src.startswith("http://") or src.startswith("https://") or src.startswith("data:")):
                return src
            try:
                return url_for("uploaded_file", filename=src)
            except Exception:
                return src

        images = {
            "instagram": to_public(social.get("instagram_image")),
            "facebook": to_public(social.get("facebook_image")),
            "twitter": to_public(social.get("twitter_image")),
            "youtube": to_public(social.get("youtube_image"))
        }

        return {"social": social, "links": links, "images": images}
    except Exception:
        return {"social": {}, "links": {}, "images": {}}
# =====================================================
# UPLOAD SETTINGS
# =====================================================
# S3 configuration (optional): set S3_BUCKET and AWS credentials in env to enable
S3_BUCKET = os.getenv("S3_BUCKET")
S3_REGION = os.getenv("S3_REGION")
S3_ENABLED = False
if boto3 and S3_BUCKET and os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"):
    try:
        s3_client = boto3.client(
            "s3",
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=S3_REGION or None
        )
        S3_ENABLED = True
        print("S3 client configured for bucket:", S3_BUCKET)
    except Exception as e:
        print("Failed to configure S3 client:", e)
        S3_ENABLED = False

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_EXT = {"png", "jpg", "jpeg", "webp"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def ensure_placeholder():
    """Ensure `static/no_image.png` exists at 1440x2160."""
    static_dir = os.path.join(BASE_DIR, "static")
    os.makedirs(static_dir, exist_ok=True)
    placeholder = os.path.join(static_dir, "no_image.png")
    if not os.path.exists(placeholder):
        try:
            img = Image.new('RGB', (1440, 2160), (240, 240, 240))
            img.save(placeholder, format='PNG')
        except Exception as e:
            print("Could not create placeholder image:", e)


ensure_placeholder()


def migrate_posters_from_addresses():
    """Move/copy any poster-like documents accidentally stored in `addresses` into `posters`.
    Criteria: document contains an `image` or `image_filename` field and at least a `title` or `subtitle`.
    This is idempotent: it avoids inserting duplicates by checking for existing poster with same image.
    """
    try:
        for doc in addresses_col.find():
            img = doc.get("image") or doc.get("image_filename")
            title = doc.get("title") or doc.get("name")
            subtitle = doc.get("subtitle") or doc.get("subtitle")
            link = doc.get("link")

            if not img or not title:
                continue

            # skip if already exists in posters (match by exact image name or data string)
            if db.posters.find_one({"image": img}):
                continue

            poster = {
                "image": img,
                "title": title,
                "subtitle": subtitle or "",
                "link": link or "#",
                "created_at": doc.get("created_at", datetime.datetime.now())
            }
            db.posters.insert_one(poster)
    except Exception as e:
        print("Poster migration error:", e)


# =====================================================
# -----------------------------
# Social image helpers + admin
# -----------------------------
SOCIAL_SIZES = {
    "instagram": (1080, 1080),
    "facebook": (820, 312),
    "twitter": (1500, 500),
    "youtube": (2560, 1440)
}


def process_and_save_social_image(file_storage, platform):
    """Resize and save an uploaded social image for `platform`.
    Returns saved filename or None.
    """
    if not file_storage or file_storage.filename == "":
        return None
    if not allowed_file(file_storage.filename):
        return None

    try:
        target_w, target_h = SOCIAL_SIZES.get(platform, (1080, 1080))
        img = Image.open(BytesIO(file_storage.read())).convert('RGB')

        w, h = img.size
        target_ratio = target_w / target_h
        img_ratio = w / h

        if img_ratio > target_ratio:
            new_w = int(h * target_ratio)
            left = (w - new_w) // 2
            img = img.crop((left, 0, left + new_w, h))
        else:
            new_h = int(w / target_ratio)
            top = (h - new_h) // 2
            img = img.crop((0, top, w, top + new_h))

        img = img.resize((target_w, target_h), Image.LANCZOS)

        out = BytesIO()
        img.save(out, format='JPEG', quality=85)
        out_bytes = out.getvalue()

        social_dir = os.path.join(app.config["UPLOAD_FOLDER"], "social")
        os.makedirs(social_dir, exist_ok=True)
        filename = f"{platform}_{int(time.time())}.jpg"
        local_path = os.path.join(social_dir, filename)
        with open(local_path, 'wb') as f:
            f.write(out_bytes)

        # return path relative to uploads folder (e.g. social/instagram_123.jpg)
        # Use POSIX-style forward slashes so stored paths work on all platforms
        return "/".join(("social", filename))

    except Exception as e:
        print(f"Error processing social image ({platform}):", e)
        return None

# CREATE DEFAULT USERS
# =====================================================
def init_mongo():
    # Skip creating default users if DB connectivity wasn't confirmed at startup.
    if not globals().get("DB_CONNECTED", False):
        print("MongoDB not connected at startup; skipping init_mongo()")
        return
    if not users_col.find_one({"email": "admin@claufe.com"}):
        users_col.insert_one({
            "name": "Admin",
            "email": "admin@claufe.com",
            "password_hash": generate_password_hash("admin123@#"),
            "role": "admin",
            "created_at": datetime.datetime.now()
        })

    if not users_col.find_one({"email": "user@claufe.com"}):
        users_col.insert_one({
            "name": "Regular User",
            "email": "user@claufe.com",
            "password_hash": generate_password_hash("user123@#"),
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
    # Log when admin access is denied to aid debugging (session cookie issues etc.)
    if session.get("role") != "admin":
        try:
            print("require_admin: blocked. session:", {"user_id": session.get("user_id"), "email": session.get("email"), "role": session.get("role")})
        except Exception:
            pass
        flash("Admin access only!", "error")
        return redirect(url_for("landing"))
    return None


# =====================================================
# PUBLIC LANDING PAGE
# =====================================================
@app.route("/")
def landing():
    products = list(products_col.find().sort("created_at", -1))
    raw_banners = list(banners_col.find().sort("created_at", -1))
    banners = []
    for b in raw_banners:
        bid = str(b.get("_id"))
        # prefer GridFS-backed URL, then data URI, then filesystem path
        if b.get("image_gridfs_id"):
            image_url = url_for("banner_image", banner_id=bid)
        elif b.get("image") and isinstance(b.get("image"), str) and b.get("image").startswith("data:"):
            image_url = b.get("image")
        elif b.get("image_filename"):
            image_url = url_for("uploaded_file", filename=b.get("image_filename"))
        else:
            image_url = url_for("static", filename="no_image.png")

        banners.append({
            "_id": bid,
            "image_url": image_url,
            "link": b.get("link"),
            "title": b.get("title"),
            "cta_text": b.get("cta_text"),
            "created_at": b.get("created_at")
        })

    # If DB is down or FORCE_LOCAL_STORAGE is enabled, also include local filesystem banners
    try:
        include_local = FORCE_LOCAL_STORAGE or not globals().get("DB_CONNECTED", False)
    except Exception:
        include_local = True

    if include_local:
        try:
            # Add any entries from banners_local.json first (explicit metadata entries)
            meta_path = os.path.join(app.config["UPLOAD_FOLDER"], "banners_local.json")
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as mf:
                        metas = json.load(mf)
                except Exception:
                    metas = []
                for m in metas:
                    rel = m.get("image_file_path")
                    if rel and not any(x.get("image_file_path") == rel for x in banners):
                        banners.insert(0, {
                            "_id": f"local_meta_{os.path.basename(rel)}",
                            "image_url": url_for("uploaded_file", filename=rel),
                            "link": "#",
                            "title": "",
                            "cta_text": "",
                            "created_at": m.get("created_at")
                        })

            # Also scan uploads/banners directory for any saved images
            banners_dir = os.path.join(app.config["UPLOAD_FOLDER"], "banners")
            if os.path.exists(banners_dir):
                for fname in sorted(os.listdir(banners_dir), reverse=True):
                    if fname.startswith('.'):
                        continue
                    rel = "/".join(("banners", fname))
                    if any(x.get("image_file_path") == rel or x.get("image_url") == url_for("uploaded_file", filename=rel) for x in banners):
                        continue
                    full = os.path.join(banners_dir, fname)
                    try:
                        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(full))
                    except Exception:
                        mtime = None
                    banners.insert(0, {
                        "_id": f"local_{fname}",
                        "image_url": url_for("uploaded_file", filename=rel),
                        "link": "#",
                        "title": "",
                        "cta_text": "",
                        "created_at": mtime
                    })
        except Exception as e:
            print("Error including local banners on landing:", e)

    posters = []
    try:
        def to_public(src):
            """Return a URL-safe image string for templates."""
            if not src:
                return url_for("static", filename="no_image.png")
            if isinstance(src, str) and (src.startswith("http://") or src.startswith("https://") or src.startswith("data:")):
                return src
            try:
                return url_for("uploaded_file", filename=src)
            except Exception:
                return src

        for p in db.posters.find().sort("created_at", -1):
            pid = str(p.get("_id"))
            posters.append({
                "_id": pid,
                "title": p.get("title", ""),
                "subtitle": p.get("subtitle", ""),
                "link": p.get("link", "#"),
                "image_url": url_for("poster_image", poster_id=pid)
            })
    except Exception:
        posters = []

    return render_template(
        "landing.html",
        products=products,
        banners=banners,
        posters=posters
    )


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    # Flash a clear message and redirect back to the referrer or banners page.
    # Returning a 413 response can prevent browsers from following the redirect
    # and the flash message from appearing in the UI, so prefer a normal redirect.
    try:
        flash("Uploaded file is too large. Max size 6 MB.", "error")
    except Exception:
        pass
    return redirect(request.referrer or url_for("admin_banners"))


@app.route("/banner_image/<string:banner_id>")
def banner_image(banner_id):
    """
    Serve banner image bytes from GridFS or fallback to filesystem/static.
    """
    try:
        doc = banners_col.find_one({"_id": ObjectId(banner_id)})
    except Exception:
        doc = None

    if not doc:
        return send_from_directory(os.path.join(BASE_DIR, "static"), "no_image.png")

    # try GridFS
    gridfs_id = doc.get("image_gridfs_id")
    if gridfs_id:
        try:
            gf_id = gridfs_id if isinstance(gridfs_id, ObjectId) else ObjectId(gridfs_id)
            grid_out = fs.get(gf_id)
            content_type = getattr(grid_out, "content_type", None) or grid_out._file.get("contentType") or grid_out._file.get("content_type") or "image/jpeg"
            data = grid_out.read()
            return Response(data, mimetype=content_type)
        except Exception as e:
            print("Error reading banner from GridFS:", e)

    # try filesystem path
    img_path = doc.get("image_filename") or doc.get("image_file_path")
    if img_path:
        try:
            return send_from_directory(app.config["UPLOAD_FOLDER"], img_path)
        except Exception as e:
            print("Error sending banner file:", e)

    # fallback
    return send_from_directory(os.path.join(BASE_DIR, "static"), "no_image.png")

@app.route("/poster_image/<string:poster_id>")
def poster_image(poster_id):
    """
    Serve poster image bytes:
    - If poster.image is a data: URI -> decode and return as image bytes with correct mimetype
    - If poster.image is a path under uploads/ -> use send_from_directory
    - Fallback to static/no_image.png when missing or on error
    """
    try:
        doc = db.posters.find_one({"_id": ObjectId(poster_id)})
    except Exception:
        doc = None

    if not doc:
        return send_from_directory(os.path.join(BASE_DIR, "static"), "no_image.png")

    # prefer explicit data URI if present
    img_data = doc.get("image")
    gridfs_id = doc.get("image_gridfs_id")
    img_path = doc.get("image_filename")

    if img_data and isinstance(img_data, str) and img_data.startswith("data:"):
        try:
            header, b64 = img_data.split(",", 1)
            content_type = "image/jpeg"
            if ";" in header and ":" in header:
                content_type = header.split(";")[0].split(":", 1)[1]
            data = base64.b64decode(b64)
            return Response(data, mimetype=content_type)
        except Exception as e:
            print("Error decoding poster data URI:", e)

    # Next, try GridFS-stored file
    if gridfs_id:
        try:
            # ensure ObjectId type
            gf_id = gridfs_id if isinstance(gridfs_id, ObjectId) else ObjectId(gridfs_id)
            grid_out = fs.get(gf_id)
            # determine content type (stored under different keys depending on how it was saved)
            content_type = getattr(grid_out, "content_type", None) or grid_out._file.get("contentType") or grid_out._file.get("content_type") or "image/jpeg"
            data = grid_out.read()
            return Response(data, mimetype=content_type)
        except Exception as e:
            print("Error reading poster from GridFS:", e)

    # Next, try filesystem path (backwards compatibility)
    if img_path:
        try:
            return send_from_directory(app.config["UPLOAD_FOLDER"], img_path)
        except Exception as e:
            print("Error sending poster file:", e)

    return send_from_directory(os.path.join(BASE_DIR, "static"), "no_image.png")


# =====================================================
# POSTER PRODUCT DETAILS
# =====================================================


@app.route("/admin_posters", methods=["GET", "POST"])
def admin_posters():
    need = require_admin()
    if need:
        return need

    if request.method == "POST":
        # Read form fields
        image = request.files.get("image")
        title = request.form.get("title", "")
        subtitle = request.form.get("subtitle", "")
        link = request.form.get("link", "#")

        if not image or image.filename == "":
            flash("Please choose an image to upload", "error")
            return redirect(url_for("admin_posters"))

        if not allowed_file(image.filename):
            flash("Invalid file type. Allowed: png, jpg, jpeg, webp", "error")
            return redirect(url_for("admin_posters"))

        # Process image, try storing in GridFS, fallback to local file
        try:
            file_bytes = image.read()
            img = Image.open(BytesIO(file_bytes)).convert('RGB')

            target_w, target_h = 1440, 2160
            target_ratio = target_w / target_h
            w, h = img.size
            img_ratio = w / h

            if img_ratio > target_ratio:
                new_w = int(h * target_ratio)
                left = (w - new_w) // 2
                img = img.crop((left, 0, left + new_w, h))
            else:
                new_h = int(w / target_ratio)
                top = (h - new_h) // 2
                img = img.crop((0, top, w, top + new_h))

            img = img.resize((target_w, target_h), Image.LANCZOS)

            out = BytesIO()
            img.save(out, format='JPEG', quality=85)
            out_bytes = out.getvalue()

            # convert to base64 data URI (kept for backward compatibility)
            content_type = 'image/jpeg'
            base64_str = "data:" + content_type + ";base64," + base64.b64encode(out_bytes).decode('utf-8')

            # Attempt GridFS storage first
            filename = f"poster_{int(time.time())}.jpg"
            file_id = None
            image_filename = None
            try:
                file_id = fs.put(out_bytes, filename=filename, content_type=content_type)
            except Exception as e:
                # fallback: save a local copy under uploads/posters/
                print("GridFS store failed, saving locally:", e)
                try:
                    posters_dir = os.path.join(app.config["UPLOAD_FOLDER"], "posters")
                    os.makedirs(posters_dir, exist_ok=True)
                    local_path = os.path.join(posters_dir, filename)
                    with open(local_path, "wb") as f:
                        f.write(out_bytes)
                    image_filename = "/".join(("posters", filename))
                except Exception as ee:
                    print("Failed to save poster locally as fallback:", ee)

        except Exception as e:
            import traceback
            traceback.print_exc()
            print("Error processing poster image:", e)
            flash("Failed to process image", "error")
            return redirect(url_for("admin_posters"))

        poster = {
            "image": base64_str,
            "image_filename": image_filename,
            "image_gridfs_id": file_id,
            "title": title,
            "subtitle": subtitle,
            "link": link or "#",
            "created_at": datetime.datetime.now()
        }

        try:
            result = db.posters.insert_one(poster)
            print("Poster inserted ID:", result.inserted_id)
        except Exception as e:
            print("Error inserting poster to DB:", e)
            flash("Failed to save poster", "error")
            return redirect(url_for("admin_posters"))

        # Also save a copy into `addresses` so it's visible in DB viewers (include filename/gridfs id)
        try:
            addresses_col.insert_one({
                "image": base64_str,
                "image_filename": image_filename,
                "image_gridfs_id": file_id,
                "title": title,
                "subtitle": subtitle,
                "link": link or "#",
                "created_at": datetime.datetime.now()
            })
        except Exception as e:
            print("Warning: failed to insert into addresses:", e)

        flash("Poster uploaded!", "success")
        return redirect(url_for("admin_posters"))

    # attempt to migrate any poster-like docs that were stored in the wrong collection
    migrate_posters_from_addresses()

    raw_posters = list(db.posters.find().sort("created_at", -1))
    posters = []
    for p in raw_posters:
        pid = str(p.get("_id"))
        posters.append({
            "_id": pid,
            "image_url": url_for("poster_image", poster_id=pid),
            "title": p.get("title", ""),
            "subtitle": p.get("subtitle", ""),
            "link": p.get("link", "#"),
            "created_at": p.get("created_at")
        })

    return render_template("admin_posters.html", posters=posters, active_page="posters")


@app.route("/admin/posters/delete/<poster_id>", methods=["POST"])
def delete_poster(poster_id):
    need = require_admin()
    if need:
        return need

    try:
        doc = db.posters.find_one({"_id": ObjectId(poster_id)})
        if doc:
            # remove GridFS file if present
            gf_id = doc.get("image_gridfs_id")
            if gf_id:
                try:
                    gf_obj_id = gf_id if isinstance(gf_id, ObjectId) else ObjectId(gf_id)
                    fs.delete(gf_obj_id)
                except Exception as e:
                    print("Warning: failed to delete GridFS file:", e)

            # remove local fallback file if present
            img_path = doc.get("image_filename")
            if img_path:
                try:
                    local_full = os.path.join(app.config["UPLOAD_FOLDER"], img_path)
                    if os.path.exists(local_full):
                        os.remove(local_full)
                except Exception as e:
                    print("Warning: failed to delete local poster file:", e)

            db.posters.delete_one({"_id": ObjectId(poster_id)})
        flash("Poster deleted", "success")
    except Exception as e:
        print("Error deleting poster:", e)
        flash("Failed to delete poster", "error")

    return redirect(url_for("admin_posters"))



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
    need = require_login()
    if need:
        return need

    data = request.get_json()

    address = {
        "user_email": session["email"],
        "full_name": data.get("full_name"),
        "phone": data.get("phone"),
        "email": session["email"],
        "address1": data.get("address1"),
        "address2": data.get("address2"),
        "city": data.get("city"),
        "state": data.get("state"),
        "pincode": data.get("pincode"),
        "created_at": datetime.datetime.now()
    }

    # remove old address
    addresses_col.delete_many({"user_email": session["email"]})

    # save new
    addresses_col.insert_one(address)

    # optional: keep in session for UI only
    session["checkout_address"] = address

    return jsonify({"saved": True})


# =====================================================
# SHIPROCKET CONFIG / HELPERS
SHIPROCKET_BASE_URL = "https://apiv2.shiprocket.in/v1/external"
SHIPROCKET_EMAIL = os.getenv("SHIPROCKET_EMAIL")
SHIPROCKET_PASSWORD = os.getenv("SHIPROCKET_PASSWORD")
SHIPROCKET_PICKUP = os.getenv("SHIPROCKET_PICKUP", "ROCKAGE")


def shiprocket_login():
    url = f"{SHIPROCKET_BASE_URL}/auth/login"

    payload = {
        "email": SHIPROCKET_EMAIL,
        "password": SHIPROCKET_PASSWORD
    }

    r = requests.post(url, json=payload)
    print("Login status:", r.status_code)
    print("Login response:", r.text)

    r.raise_for_status()
    return r.json()["token"]


def shiprocket_create_order(order, address):
    token = shiprocket_login()

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "order_id": str(order["_id"]),
        "order_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "pickup_location": SHIPROCKET_PICKUP,

        "billing_customer_name": address["full_name"],
        "billing_last_name": "",
        "billing_address": address["address1"],
        "billing_address_2": address.get("address2", ""),
        "billing_city": address["city"],
        "billing_pincode": address["pincode"],
        "billing_state": address["state"],
        "billing_country": "India",
        "billing_email": address["email"],
        "billing_phone": address["phone"],

        "shipping_is_billing": True,

        "order_items": [
            {
                "name": i["name"],
                "sku": f"SKU-{i['product_id']}",
                "units": int(i["quantity"]),
                "selling_price": float(i["price"])
            }
            for i in order["items"]
        ],

        "payment_method": "Prepaid",
        "sub_total": float(order["total"]),

        "length": 10,
        "breadth": 10,
        "height": 10,
        "weight": 0.5
    }

    url = f"{SHIPROCKET_BASE_URL}/orders/create/adhoc"
    r = requests.post(url, json=payload, headers=headers)
    print("Create order response:", r.text)

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

    # ADDRESS FROM FRONTEND (sent in verify-payment body)
    # The frontend code sends: full_name, phone, address, pincode, city, state
    pay_address = session.get("checkout_address", {})
    
    if data.get("full_name"):
        pay_address = {
            "full_name": data.get("full_name"),
            "phone": data.get("phone"),
            "email": session["email"],
            "address1": data.get("address"),  # Frontend sends 'address'
            "address2": data.get("address2", ""),
            "city": data.get("city"),
            "state": data.get("state"),
            "pincode": data.get("pincode")
        }

    # SAVE ORDER
    new_order_id = orders_col.insert_one({
        "user_email": session["email"],
        "items": items,
        "total": total,
        "status": "Paid",
        "payment_id": payment_id,
        "order_id": order_id,
        "payment_method": "Prepaid",
        "address": pay_address,  # Use the payload address
        "created_at": datetime.datetime.now()
    }).inserted_id

    order_doc = orders_col.find_one({"_id": new_order_id})

    # CREATE SHIPROCKET ORDER
    try:
        ship_data = shiprocket_create_order(order_doc, pay_address)
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
        import traceback
        traceback.print_exc()
        print(f"Shiprocket Error [Order {new_order_id}]: {e}")
        # record error on order for debugging
        orders_col.update_one({"_id": new_order_id}, {"$set": {
            "shiprocket_error": str(e), 
            "shiprocket_error_time": datetime.datetime.now()
        }})

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
    try :
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

        if not file or file.filename == "":
            flash("Please choose an image to upload", "error")
            return redirect(url_for("admin_banners"))

        if not allowed_file(file.filename):
            flash("Invalid file type. Allowed: png, jpg, jpeg, webp", "error")
            return redirect(url_for("admin_banners"))

        try:
            # Debug info to help diagnose upload failures
            try:
                print("Admin banner upload - session:", session.get('email'), session.get('role'))
                print("Headers Content-Length:", request.headers.get('Content-Length'))
                print("Request content_length:", request.content_length)
            except Exception:
                pass

            # Read the uploaded bytes into memory once and validate size.
            try:
                file.stream.seek(0)
            except Exception:
                pass

            file_bytes = file.read() or b""
            file_size = len(file_bytes)
            print(f"Uploaded file bytes: {file_size}")

            # server-side guard: reject files > 5 MB (UI recommends 5MB)
            max_bytes = 5 * 1024 * 1024
            if file_size > max_bytes:
                flash("Uploaded file is too large. Max allowed is 5 MB.", "error")
                return redirect(url_for("admin_banners"))

            if not file_bytes:
                flash("Uploaded file appears empty.", "error")
                return redirect(url_for("admin_banners"))

            img = Image.open(BytesIO(file_bytes)).convert('RGB')

            # target 16:9 and 1920x1080
            target_w, target_h = 1920, 1080
            target_ratio = target_w / target_h
            w, h = img.size
            img_ratio = w / h

            if img_ratio > target_ratio:
                # image too wide -> crop left/right
                new_w = int(h * target_ratio)
                left = (w - new_w) // 2
                img = img.crop((left, 0, left + new_w, h))
            else:
                # image too tall -> crop top/bottom
                new_h = int(w / target_ratio)
                top = (h - new_h) // 2
                img = img.crop((0, top, w, top + new_h))

            img = img.resize((target_w, target_h), Image.LANCZOS)

            out = BytesIO()
            quality = 85
            img.save(out, format='JPEG', quality=quality)
            out_bytes = out.getvalue()

            # Ensure final size under 5MB by lowering quality if necessary
            max_bytes = 5 * 1024 * 1024
            while len(out_bytes) > max_bytes and quality > 60:
                quality -= 5
                out = BytesIO()
                img.save(out, format='JPEG', quality=quality)
                out_bytes = out.getvalue()

            # prepare base64 data URI for backup/inline use
            content_type = 'image/jpeg'
            base64_str = "data:" + content_type + ";base64," + base64.b64encode(out_bytes).decode('utf-8')

            # Try storing processed bytes in GridFS first (preferred).
            file_id = None
            orig_name = os.path.splitext(file.filename)[0]
            safe_base = secure_filename(orig_name) or f"banner_{int(time.time())}"
            safe_name = f"{safe_base}_{int(time.time())}.jpg"
            image_file_path = None

            try:
                file_id = fs.put(out_bytes, filename=safe_name, content_type=content_type)
            except Exception as e:
                print("GridFS store failed for banner:", e)
                # don't return yet; we'll attempt local filesystem save below as a fallback

            # If GridFS succeeded, we may still want a local copy for direct serving
            # but avoid writing to disk on read-only environments. Attempt local save
            # only if filesystem appears writable.
            local_saved = False
            banners_dir = os.path.join(app.config["UPLOAD_FOLDER"], "banners")
            try:
                os.makedirs(banners_dir, exist_ok=True)
                local_path = os.path.join(banners_dir, safe_name)
                with open(local_path, "wb") as out_f:
                    out_f.write(out_bytes)
                image_file_path = "/".join(("banners", safe_name))
                local_saved = True
            except OSError as e:
                # common on serverless/read-only filesystems
                print("Local filesystem save failed (possibly read-only):", e)
                local_saved = False
            except Exception as e:
                print("Unexpected error saving local banner copy:", e)
                local_saved = False

            # If FORCE_LOCAL_STORAGE is explicitly requested but local save failed,
            # inform admin and stop (cannot persist banner locally).
            if FORCE_LOCAL_STORAGE and not local_saved:
                flash("Server cannot write files to local disk (read-only). Enable MongoDB or configure external storage (S3).", "error")
                return redirect(url_for("admin_banners"))

            # Insert into MongoDB with retries for transient errors
            insert_doc = {
                "image": base64_str,
                "image_filename": image_file_path,
                "image_file_path": image_file_path,
                "image_gridfs_id": file_id,
                "created_at": datetime.datetime.now()
            }

            insert_success = False
            last_exc = None
            for attempt in range(1, 4):
                try:
                    result = banners_col.insert_one(insert_doc)
                    print(f"Banner inserted ID: {result.inserted_id} (attempt {attempt})")
                    insert_success = True
                    break
                except PyMongoError as e:
                    print(f"Mongo insert attempt {attempt} failed:", e)
                    last_exc = e
                    time.sleep(0.5 * attempt)

            if not insert_success:
                # Persist a small retry file locally so ops team can recover/inspect
                pending_dir = os.path.join(app.config["UPLOAD_FOLDER"], "banners_pending")
                try:
                    os.makedirs(pending_dir, exist_ok=True)
                    pending_name = f"pending_{safe_name}_{int(time.time())}.json"
                    pending_path = os.path.join(pending_dir, pending_name)
                    payload = {
                        "error": str(last_exc),
                        "insert_doc": {
                            "image_filename": image_file_path,
                            "image_gridfs_id": file_id,
                            "created_at": insert_doc["created_at"].isoformat()
                        }
                    }
                    with open(pending_path, "w", encoding="utf-8") as pf:
                        json.dump(payload, pf, ensure_ascii=False, indent=2)
                    print("Saved pending banner metadata to:", pending_path)
                except Exception as e:
                    print("Failed to write pending banner file:", e)
                # Let admin know we saved file locally but DB failed
                flash("Banner saved locally but failed to store in database (will retry).", "warning")
                return redirect(url_for("admin_banners"))

            flash("Banner uploaded!", "success")
            return redirect(url_for("admin_banners"))

        except Exception as e:
            import traceback
            traceback.print_exc()
            print("Error saving banner:", e)
            # Provide a helpful flash for the admin so they see what went wrong.
            try:
                flash(f"Failed to upload banner: {str(e)}", "error")
            except Exception:
                flash("Failed to upload banner", "error")
            return redirect(url_for("admin_banners"))

    raw = list(banners_col.find().sort("created_at", -1))
    banners = []
    for b in raw:
        # compute a public URL for preview (GridFS -> /banner_image/<id>,
        # otherwise data URI or filesystem uploads path)
        bid = str(b.get("_id"))
        if b.get("image_gridfs_id"):
            image_url = url_for("banner_image", banner_id=bid)
        elif b.get("image") and isinstance(b.get("image"), str) and b.get("image").startswith("data:"):
            image_url = b.get("image")
        elif b.get("image_filename"):
            image_url = url_for("uploaded_file", filename=b.get("image_filename"))
        else:
            image_url = url_for("static", filename="no_image.png")

        banners.append({
            "_id": bid,
            "image": b.get("image"),
            "image_file_path": b.get("image_file_path"),
            "image_filename": b.get("image_filename"),
            "image_gridfs_id": b.get("image_gridfs_id"),
            "image_url": image_url,
            "created_at": b.get("created_at")
        })

    # If DB is down or FORCE_LOCAL_STORAGE is enabled, also include local filesystem banners
    try:
        include_local = FORCE_LOCAL_STORAGE or not globals().get("DB_CONNECTED", False)
    except Exception:
        include_local = True

    if include_local:
        try:
            banners_dir = os.path.join(app.config["UPLOAD_FOLDER"], "banners")
            if os.path.exists(banners_dir):
                for fname in sorted(os.listdir(banners_dir), reverse=True):
                    # skip hidden files
                    if fname.startswith('.'):
                        continue
                    rel = "/".join(("banners", fname))
                    # avoid duplicates if DB already returned this path
                    if any(x.get("image_file_path") == rel for x in banners):
                        continue
                    full = os.path.join(banners_dir, fname)
                    try:
                        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(full))
                    except Exception:
                        mtime = None
                    banners.insert(0, {
                        "_id": f"local_{fname}",
                        "image": None,
                        "image_file_path": rel,
                        "image_filename": rel,
                        "image_gridfs_id": None,
                        "image_url": url_for("uploaded_file", filename=rel),
                        "created_at": mtime
                    })
        except Exception as e:
            print("Error including local banners:", e)

    return render_template("admin_banners.html", banners=banners)


@app.route("/admin/banner/delete/<string:banner_id>", methods=["POST"])
def delete_banner(banner_id):
    need = require_admin()
    if need:
        return need

    banner = banners_col.find_one({"_id": ObjectId(banner_id)})
    if banner:
        # Remove GridFS file if present
        gf_id = banner.get("image_gridfs_id")
        if gf_id:
            try:
                gf_obj_id = gf_id if isinstance(gf_id, ObjectId) else ObjectId(gf_id)
                fs.delete(gf_obj_id)
            except Exception as e:
                print("Warning: failed to delete banner GridFS file:", e)

        # If a local file was saved, try to remove it. Skip deletion for
        # data: URIs or external http(s) URLs.
        img_path = banner.get("image_file_path") or banner.get("image_filename") or banner.get("image")
        if img_path and isinstance(img_path, str) and not (
            img_path.startswith("data:") or img_path.startswith("http://") or img_path.startswith("https://")
        ):
            try:
                local_full = os.path.join(app.config["UPLOAD_FOLDER"], img_path)
                if os.path.exists(local_full):
                    os.remove(local_full)
            except Exception as e:
                print("Warning: failed to delete banner file:", e)

        banners_col.delete_one({"_id": ObjectId(banner_id)})

    flash("Banner deleted!", "success")
    return redirect(url_for("admin_banners"))


@app.route("/admin/social-links", methods=["GET", "POST"])
def admin_social_links():
    need = require_admin()
    if need:
        return need

    if request.method == "POST":
        # template uses `instagram`, `facebook`, `twitter`, `youtube` fields
        instagram_url = request.form.get("instagram")
        facebook_url = request.form.get("facebook")
        twitter_url = request.form.get("twitter")
        youtube_url = request.form.get("youtube")

        data = {
            "instagram_url": instagram_url,
            "facebook_url": facebook_url,
            "twitter_url": twitter_url,
            "youtube_url": youtube_url,
            "updated_at": datetime.datetime.now()
        }

        # files from template names: instagram_img, facebook_img, twitter_img, youtube_img
        try:
            inst_file = request.files.get("instagram_img")
            fb_file = request.files.get("facebook_img")
            tw_file = request.files.get("twitter_img")
            yt_file = request.files.get("youtube_img")

            if inst_file:
                saved = process_and_save_social_image(inst_file, "instagram")
                if saved:
                    data["instagram_image"] = saved
            if fb_file:
                saved = process_and_save_social_image(fb_file, "facebook")
                if saved:
                    data["facebook_image"] = saved
            if tw_file:
                saved = process_and_save_social_image(tw_file, "twitter")
                if saved:
                    data["twitter_image"] = saved
            if yt_file:
                saved = process_and_save_social_image(yt_file, "youtube")
                if saved:
                    data["youtube_image"] = saved
        except Exception as e:
            print("Error processing social upload:", e)

        social_col.update_one({}, {"$set": data}, upsert=True)
        flash("Social links updated!", "success")
        return redirect(url_for("admin_social_links"))

    social = social_col.find_one() or {}

    # Build `links` and `images` expected by template
    links = {
        "instagram": social.get("instagram_url"),
        "facebook": social.get("facebook_url"),
        "twitter": social.get("twitter_url"),
        "youtube": social.get("youtube_url")
    }

    def to_public(src):
        if not src:
            return None
        if isinstance(src, str) and (src.startswith("http://") or src.startswith("https://") or src.startswith("data:")):
            return src
        # assume it's a path relative to uploads/ (e.g. social/filename.jpg)
        try:
            return url_for("uploaded_file", filename=src)
        except Exception:
            return src

    images = {
        "instagram": to_public(social.get("instagram_image")),
        "facebook": to_public(social.get("facebook_image")),
        "twitter": to_public(social.get("twitter_image")),
        "youtube": to_public(social.get("youtube_image"))
    }

    return render_template("admin_social_links.html", social=social, links=links, images=images)


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

    raw_products = list(products_col.find().sort("created_at", -1))
    products = []
    for p in raw_products:
        products.append({
            "_id": str(p.get("_id")),
            "name": p.get("name"),
            "price": p.get("price"),
            "created_at": p.get("created_at"),
            "image_filename": p.get("image_filename")
        })

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
        try:
            name = request.form.get("name", "").strip()
            price_raw = request.form.get("price", "").strip()
            old_price_raw = request.form.get("old_price", "").strip()
            description = request.form.get("description", "").strip()
            selected_sizes = request.form.getlist("sizes")

            if not name or not price_raw:
                flash("Product Name and Price are required!", "error")
                return redirect(url_for("add_product"))

            try:
                price = float(price_raw)
            except ValueError:
                flash("Invalid Price value! Please enter a number.", "error")
                return redirect(url_for("add_product"))

            old_price = None
            if old_price_raw:
                try:
                    old_price = float(old_price_raw)
                except ValueError:
                    pass # Just ignore if invalid, since it is optional

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
                    # Convert to Base64
                    content_type = file.content_type
                    file_content = file.read()
                    base64_str = "data:" + content_type + ";base64," + base64.b64encode(file_content).decode('utf-8')
                    saved_images.append(base64_str)

            if not saved_images:
                flash("Upload at least one image", "error")
                return redirect(url_for("add_product"))

            main_image = saved_images[0]

            # insert DB
            products_col.insert_one({
                "name": name,
                "description": description,
                "price": price,
                "old_price": old_price,
                "image_filename": main_image,
                "images": saved_images,
                "sizes": selected_sizes,
                "stock": stock,
                "rating": rating,     # ⭐️ Stored Here
                "created_at": datetime.datetime.now()
            })

            flash("Product added!", "success")
            return redirect(url_for("admin_products"))

        except Exception as e:
            print(f"Error in add_product: {e}")
            flash(f"An error occurred: {str(e)}", "error")
            return redirect(url_for("add_product"))

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
    # Disable the auto-reloader on Windows to avoid OSError [WinError 10038]
    app.run(debug=False, use_reloader=False)
