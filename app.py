import os
from flask import Flask, render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Product
from forms import RegistrationForm, LoginForm, ProductForm

app = Flask(__name__)
app.config["SECRET_KEY"] = "mysecret"
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "instance", "ecommerce.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered. Please login.", "danger")
            return redirect(url_for("login"))
        hashed_pw = generate_password_hash(form.password.data, method="pbkdf2:sha256")
        user = User(email=form.email.data, password_hash=hashed_pw, role="user")
        db.session.add(user)
        db.session.commit()
        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if not user:
            flash("No account found. Please register.", "warning")
            return redirect(url_for("register"))

        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid email or password.", "danger")
    return render_template("login.html", form=form)


@app.route("/home")
@login_required
def home():
    products = Product.query.all()
    return render_template("home.html", products=products)


@app.route("/add_product", methods=["GET", "POST"])
@login_required
def add_product():
    if current_user.role != "admin":
        flash("Only admin can add products!", "danger")
        return redirect(url_for("home"))

    form = ProductForm()
    if form.validate_on_submit():
        product = Product(name=form.name.data, price=form.price.data, description=form.description.data)
        db.session.add(product)
        db.session.commit()
        flash("Product added successfully!", "success")
        return redirect(url_for("home"))
    return render_template("add_product.html", form=form)


@app.route("/edit_product/<int:product_id>", methods=["GET", "POST"])
@login_required
def edit_product(product_id):
    if current_user.role != "admin":
        flash("Only admin can edit products!", "danger")
        return redirect(url_for("home"))

    product = Product.query.get_or_404(product_id)
    form = ProductForm(obj=product)
    if form.validate_on_submit():
        product.name = form.name.data
        product.price = form.price.data
        product.description = form.description.data
        db.session.commit()
        flash("Product updated successfully!", "success")
        return redirect(url_for("home"))
    return render_template("edit_product.html", form=form, product=product)


@app.route("/delete_product/<int:product_id>")
@login_required
def delete_product(product_id):
    if current_user.role != "admin":
        flash("Only admin can delete products!", "danger")
        return redirect(url_for("home"))

    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash("Product deleted successfully!", "info")
    return redirect(url_for("home"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    os.makedirs(os.path.join(basedir, "instance"), exist_ok=True)
    with app.app_context():
        db.create_all()

        # ensure admin exists
        admin = User.query.filter_by(email="admin@example.com").first()
        if not admin:
            hashed_pw = generate_password_hash("admin123", method="pbkdf2:sha256")
            admin = User(email="admin@example.com", password_hash=hashed_pw, role="admin")
            db.session.add(admin)
            db.session.commit()

    app.run(debug=False)

