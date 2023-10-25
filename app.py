from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import mysql.connector
from connect import get_db_connection
from flask_bcrypt import Bcrypt

# Create a Flask application
app = Flask(__name__, static_url_path='/static')
app.secret_key = 'secret_key'  # Replace with a secret key

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Initialize Bcrypt
bcrypt = Bcrypt(app)

# Define a User class
class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

# Create a function to load a user by user_id
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/')
def index():
    # Establish a database connection
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Execute a sample SQL query
        cursor.execute("SELECT * FROM UserAccount")
        results = cursor.fetchall()

        # Close the cursor and connection
        cursor.close()
        conn.close()

        return render_template('index.html', data=results)

    except Exception as e:
        return "Error: " + str(e)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']

        try:
            # Hash the password before storing it in the database
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Establish a database connection
            conn = get_db_connection()
            cursor = conn.cursor()

            # Insert user registration data, including the hashed password, into the UserAccount table
            insert_query = "INSERT INTO UserAccount (Username, Password, FirstName, LastName, Email) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(insert_query, (username, hashed_password, firstname, lastname, email))
            conn.commit()

            # Close the cursor and connection
            cursor.close()
            conn.close()

            flash('Registration successful', 'success')
            # Instead of immediate redirection, render a registration success page
            return render_template('registration_success.html')

        except mysql.connector.Error as e:
            return "Error: " + str(e)

    return render_template('registration.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT UserID, Password FROM UserAccount WHERE Username = %s", (username,))
            result = cursor.fetchone()

            if result:
                user_id, hashed_password_db = result
                if bcrypt.check_password_hash(hashed_password_db, password):
                    user = User(user_id)
                    login_user(user)
                    flash('Login successful', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid password', 'danger')
            else:
                flash('User not found', 'danger')

            cursor.close()
            conn.close()

        except mysql.connector.Error as e:
            flash('Error: ' + str(e), 'danger')

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
