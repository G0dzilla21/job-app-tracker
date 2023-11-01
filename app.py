from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
from connect import get_db_connection
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import FileField
from flask_wtf.file import FileRequired
from dotenv import load_dotenv
import os
import pandas as pd
import tempfile
import boto3
import plotly
import plotly.graph_objs as go
from functools import wraps

load_dotenv()

aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")

s3 = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

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

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT UserID, Username, UserRole FROM UserAccount WHERE UserID = %s", (user_id,))
        user_data = cursor.fetchone()
        cursor.close()
        conn.close()

        if user_data:
            user_id, username, user_role = user_data
            user = User(user_id)
            user.username = username
            user.UserRole = user_role  # Assign the UserRole attribute

            return user
        else:
            return None  # Return None if the user is not found

    except Exception as e:
        return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.UserRole == 'admin':
            return f(*args, **kwargs)
        else:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))  # Redirect to the home page or another suitable page
    return decorated_function

@app.route('/')
def index():
    if current_user.is_authenticated:
        user_id = current_user.id

        # Query the database to retrieve roles
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Replace 'your_table' with the actual table name where applications are stored
            cursor.execute("SELECT * FROM UserAccount WHERE UserID = %s AND UserRole = 'admin'", (user_id,))
            roles = cursor.fetchall()
            print(roles)
            # Close the cursor and connection
            cursor.close()
            conn.close()

            return render_template('index.html', roles=roles) 
        
        except Exception as e:
            return "Error: " + str(e)
    return render_template('index.html')
    

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None  # Initialize the "error" variable

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']

        if password != confirm_password:
            error = "Password and confirmation do not match"

        if error:
            flash(error, 'danger')
        else:
            try:
                # Hash the password before storing it in the database
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

                # Establish a database connection
                conn = get_db_connection()
                cursor = conn.cursor()

                # Insert user registration data, including the hashed password, into the UserAccount table
                insert_query = "INSERT INTO UserAccount (Username, Password, FirstName, LastName, Email, UserRole) VALUES (%s, %s, %s, %s, %s, 'user')"
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

    return render_template('registration.html', error=error)


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
                    return redirect(url_for('index'))
                else:
                    flash('Invalid password', 'danger')
            else:
                flash('User not found', 'danger')

            cursor.close()
            conn.close()

        except mysql.connector.Error as e:
            flash('Error: ' + str(e), 'danger')

    return render_template('login.html')


# Create a class for the file upload form
class UploadForm(FlaskForm):
    excel_file = FileField('Excel File', validators=[FileRequired()])

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        
        if uploaded_file:
            try:
                # Get the UserID of the logged-in user
                user_id = current_user.id  # Assuming current_user.id contains the UserID

                # Create a temporary directory to store the converted CSV file
                temp_dir = tempfile.mkdtemp()

                # Define the path for the temporary Excel and CSV files
                excel_path = os.path.join(temp_dir, 'uploaded_excel.xlsx')
                csv_path = os.path.join(temp_dir, 'uploaded_csv.csv')

                # Save the uploaded Excel file to the temporary directory
                uploaded_file.save(excel_path)

                # Read the Excel file and save it as CSV
                excel_data = pd.read_excel(excel_path)
                excel_data.to_csv(csv_path, index=False)

                print(excel_data)

                # Set the S3 bucket and file key with the UserID
                bucket = 'applications-tracker'
                file_key = f'user_applications/{user_id}_{uploaded_file.filename}.csv'

                # Upload the CSV file to the S3 bucket
                s3.upload_file(Filename=csv_path, Bucket=bucket, Key=file_key)

                # Clean up the temporary directory
                os.remove(excel_path)
                os.remove(csv_path)
                os.rmdir(temp_dir)

                # Redirect or render the success message
                return render_template('upload.html', upload_success=True)
            except Exception as e:
                print('Error: ' + str(e))
         
    return render_template('upload.html', upload_success=False)

@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    user_id = current_user.id

    # Query the database to retrieve roles
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Replace 'your_table' with the actual table name where applications are stored
        cursor.execute("SELECT * FROM UserAccount WHERE UserID = %s AND UserRole = 'admin'", (user_id,))
        roles = cursor.fetchall()
        print(roles)
        # Close the cursor and connection
        cursor.close()
        conn.close()

        return render_template('admin_dashboard.html', roles=roles)

    except Exception as e:
        return "Error: " + str(e)
    

@app.route('/applications')
@login_required
def applications():
    # Retrieve the current user's ID
    user_id = current_user.id
    
    # Query the database to retrieve applications for the current user
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Replace 'your_table' with the actual table name where applications are stored
        cursor.execute("SELECT * FROM Applications WHERE UserID = %s", (user_id,))
        applications = cursor.fetchall()
        # print(applications)
        # Close the cursor and connection
        cursor.close()
        conn.close()

        return render_template('applications.html', applications=applications)

    except Exception as e:
        return "Error: " + str(e)
    

@app.route('/edit_application/<int:application_id>', methods=['GET', 'POST'])
@login_required
def edit_application(application_id):
    if request.method == 'POST':
        # Handle form submission for editing
        # Retrieve form data and update the application in the database
        company = request.form.get('company')
        position = request.form.get('position')
        application_date = request.form.get('application_date')
        location = request.form.get('location')
        link = request.form.get('link')
        feedback = request.form.get('feedback')

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Update the application in the database based on application_id
            update_query = "UPDATE Applications SET Company = %s, Position = %s, ApplicationDate = %s, Location = %s, Link = %s, Feedback = %s WHERE ApplicationID = %s"
            cursor.execute(update_query, (company, position, application_date, location, link, feedback, application_id))
            conn.commit()

            cursor.close()
            conn.close()

            flash('Application updated successfully', 'success')
            return redirect(url_for('applications'))

        except mysql.connector.Error as e:
            flash('Error: ' + str(e), 'danger')

    else:
        # Retrieve the application details from the database using the application_id
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM Applications WHERE ApplicationID = %s", (application_id,))
            application = cursor.fetchone()

            cursor.close()
            conn.close()

            return render_template('edit_application.html', application=application, application_id=application_id)

        except mysql.connector.Error as e:
            flash('Error: ' + str(e), 'danger')

    return redirect(url_for('applications'))

@app.route('/delete_application/<int:application_id>', methods=['GET', 'POST'])
@login_required
def delete_application(application_id):
    if request.method == 'POST':
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Delete the application from the database based on application_id
            delete_query = "DELETE FROM Applications WHERE ApplicationID = %s"
            cursor.execute(delete_query, (application_id,))
            conn.commit()

            cursor.close()
            conn.close()

            flash('Application deleted successfully', 'success')
            return redirect(url_for('applications'))

        except mysql.connector.Error as e:
            flash('Error: ' + str(e), 'danger')

    else:
        return render_template('delete_application.html', application_id=application_id)   

@app.route('/analysis')
@login_required
@admin_required
def analysis():
    user_id = current_user.id

    # Query the database to retrieve roles
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Replace 'your_table' with the actual table name where applications are stored
        cursor.execute("SELECT * FROM UserAccount WHERE UserID = %s AND UserRole = 'admin'", (user_id,))
        roles = cursor.fetchall()
        print(roles)
        # Close the cursor and connection
        cursor.close()
        conn.close()

        return render_template('analysis.html', roles=roles) 
    
    except Exception as e:
        return "Error: " + str(e)

@app.route('/manage_users')
@login_required
@admin_required
def manage_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT UserID, Username, UserRole FROM UserAccount")
        users = cursor.fetchall()

        cursor.close()
        conn.close()

        return render_template('manage_users.html', users=users)

    except mysql.connector.Error as e:
        flash('Error: ' + str(e), 'danger')

    return render_template('manage_users.html')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    if request.method == 'POST':
        new_role = request.form.get('new_role')

        if new_role in ['user', 'moderator', 'admin']:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()

                # Update the user's role in the database based on user_id
                update_query = "UPDATE UserAccount SET UserRole = %s WHERE UserID = %s"
                cursor.execute(update_query, (new_role, user_id))
                conn.commit()

                cursor.close()
                conn.close()

                flash('User role updated successfully', 'success')
                return redirect(url_for('manage_users'))

            except mysql.connector.Error as e:
                flash('Error: ' + str(e), 'danger')

    else:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT UserID, Username, UserRole FROM UserAccount WHERE UserID = %s", (user_id,))
            user = cursor.fetchone()

            cursor.close()
            conn.close()

            return render_template('edit_user.html', user=user)

        except mysql.connector.Error as e:
            flash('Error: ' + str(e), 'danger')

    return redirect(url_for('manage_users'))

@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def delete_user(user_id):
    if current_user.is_authenticated and current_user.UserRole == 'admin':
        if request.method == 'POST':
            try:
                conn = get_db_connection()
                cursor = conn.cursor()

                # Delete the user from the database based on user_id
                delete_query = "DELETE FROM UserAccount WHERE UserID = %s"
                cursor.execute(delete_query, (user_id,))
                conn.commit()

                cursor.close()
                conn.close()

                flash('User deleted successfully', 'success')
                return redirect(url_for('manage_users'))  # Redirect to the user management page

            except mysql.connector.Error as e:
                flash('Error: ' + str(e), 'danger')

        else:
            return render_template('delete_user.html', user_id=user_id)  # Render the confirmation page

    else:
        flash('You do not have permission to delete users.', 'danger')
        return redirect(url_for('manage_users'))  # Redirect back to the user management page


@app.route('/dashboard', methods=['GET', 'POST'])
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
