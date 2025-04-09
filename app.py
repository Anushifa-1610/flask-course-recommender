from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import pandas as pd
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Database setup
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Load and preprocess course dataset
try:
    all_courses_df = pd.read_csv("merged_courses_data.csv")

    all_courses_df.rename(columns={
        "course_title": "title",
        "subject": "category",
        "url": "course_link",
        "course_difficulty": "difficulty",
        "content_duration": "duration",
        "Free/Paid": "is_paid",
        "course_organization": "platform",
        "num_subscribers": "subscribers"
    }, inplace=True)

    # Ensure required columns exist
    required_columns = ["title", "category", "course_link", "difficulty", "duration", "is_paid", "platform", "subscribers"]
    for col in required_columns:
        if col not in all_courses_df.columns:
            all_courses_df[col] = None  

    # Drop duplicates & reset index
    all_courses_df = all_courses_df.drop_duplicates(subset=["title"]).reset_index(drop=True)

    # ✅ Convert all text to lowercase for better matching
    all_courses_df["clean_title"] = all_courses_df["title"].astype(str).str.lower()
    all_courses_df["clean_category"] = all_courses_df["category"].astype(str).str.lower()

    print("✅ Dataset Loaded Successfully! Columns:", all_courses_df.columns.tolist()) 

except Exception as e:
    print(f"❌ Error loading course dataset: {e}")
    all_courses_df = pd.DataFrame(columns=["title", "category", "course_link", "difficulty", "duration", "is_paid", "platform", "subscribers"])

# Preprocessing function
def preprocess_text(text):
    """Convert text to lowercase & remove special characters."""
    if pd.isna(text):
        return ""
    text = text.lower().strip()  
    text = re.sub(r'[^a-zA-Z0-9\s]', '', text)  # Remove special characters
    return text

def recommend_courses_by_interest(user_input, top_n=10):
    """Find relevant courses for multiple keywords."""
    if not user_input.strip():
        return []

    if all_courses_df.empty or "title" not in all_courses_df.columns:
        return []

    # Preprocess user input
    keywords = [preprocess_text(keyword) for keyword in user_input.split(",")]

    matched_courses = pd.DataFrame(columns=["title", "category", "course_link", "difficulty", "duration", "is_paid", "platform", "subscribers"])

    for keyword in keywords:
        if keyword:  # Skip empty keywords
            filtered_courses = all_courses_df[
                (all_courses_df["clean_title"].str.contains(keyword, na=False)) |
                (all_courses_df["clean_category"].str.contains(keyword, na=False))
            ].copy()

            matched_courses = pd.concat([matched_courses, filtered_courses], ignore_index=True)

    # Sort results by the most subscribers
    if "subscribers" in matched_courses.columns:
        matched_courses = matched_courses.sort_values(by="subscribers", ascending=False)

    # Drop duplicates and return top N courses
    return matched_courses.drop_duplicates(subset=["title"]).head(top_n).to_dict(orient="records")

# Routes
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("signup"))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already exists! Try logging in.", "danger")
            return redirect(url_for("login"))

        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Signup successful! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid credentials! Please try again.", "danger")
    return render_template("index.html")

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    recommendations = []
    if request.method == "POST":
        user_input = request.form["interests"]
        recommendations = recommend_courses_by_interest(user_input)

        if not recommendations:
            flash("No matching courses found. Try different keywords!", "warning")

    return render_template("dashboard.html", recommendations=recommendations)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
