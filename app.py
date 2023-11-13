from datetime import datetime
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
import pymysql
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

                last_user_id = cursor.lastrowid
                # Use raw SQL with a cursor to either update or insert the privacy settings
                sql_statement = """
                    INSERT INTO DataPrivacy (UserID, IsDataPrivate) VALUES (%s, %s)
                """

                cursor.execute(
                    sql_statement,
                    (last_user_id, 0)
                )
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


def insert_application(cursor, user_id, company, position, application_date, location, link, feedback):
    # Prepare the SQL query to insert the new application data, including DateAdded
    insert_query = """
        INSERT INTO Applications (UserID, Company, Position, ApplicationDate, Location, Link, Feedback, DateAdded)
        VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
    """
    data = (user_id, company, position, application_date, location, link, feedback)

    # Execute the query with the data
    cursor.execute(insert_query, data)
    # Return the last inserted application ID
    return cursor.lastrowid

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
    return render_template('admin_dashboard.html')  

@app.route('/applications')
@login_required
def applications():
    # Retrieve the current user's ID
    user_id = current_user.id
    
    # Query the database to retrieve applications and interviews for the current user
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Replace 'your_table' with the actual table name where applications are stored
        # Modify it to join the Applications and Interviews tables:
        cursor.execute("""
            SELECT Applications.*, Interviews.InterviewID
            FROM Applications
            LEFT JOIN Interviews ON Applications.ApplicationID = Interviews.ApplicationID
            WHERE Applications.UserID = %s
        """, (user_id,))
        applications = cursor.fetchall()

        # Close the cursor and connection
        cursor.close()
        conn.close()

        return render_template('applications.html', applications=applications)

    except Exception as e:
        return "Error: " + str(e)
    
@app.route('/new_application', methods=['GET'])
@login_required
def new_application():
    return render_template('new_application.html')

    
@app.route('/create_application', methods=['POST'])
@login_required
def create_application():
    if request.method == 'POST':
        company = request.form.get('company')
        position = request.form.get('position')
        application_date = request.form.get('application_date')
        location = request.form.get('location')
        link = request.form.get('link')
        feedback = request.form.get('feedback')

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Prepare the SQL query to insert the new application data, including DateAdded
            insert_query = """
                INSERT INTO Applications (UserID, Company, Position, ApplicationDate, Location, Link, Feedback, DateAdded)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """
            user_id = current_user.id  # Get the current user's ID
            data = (user_id, company, position, application_date, location, link, feedback)

            # Execute the query with the data
            cursor.execute(insert_query, data)
            conn.commit()

            # Get the last inserted ApplicationID
            last_application_id = cursor.lastrowid

            # Prepare the SQL query to insert into the Interviews table
            insert_interview_query = """
                INSERT INTO Interviews (ApplicationID)
                VALUES (%s)
            """
            interview_data = (last_application_id,)

            # Execute the query with the data
            cursor.execute(insert_interview_query, interview_data)
            conn.commit()

            flash('New application and interview created successfully', 'success')
            return redirect('/applications')

        except mysql.connector.Error as e:
            flash('Error: ' + str(e), 'danger')

        finally:
            cursor.close()
            conn.close()

    else:
        flash('Invalid request', 'danger')
        return redirect('/new_application')
    

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

            # Delete from Interviews table first
            delete_interview_query = "DELETE FROM Interviews WHERE ApplicationID = %s"
            cursor.execute(delete_interview_query, (application_id,))
            conn.commit()

            # Then delete from Applications table
            delete_application_query = "DELETE FROM Applications WHERE ApplicationID = %s"
            cursor.execute(delete_application_query, (application_id,))
            conn.commit()

            cursor.close()
            conn.close()

            flash('Application deleted successfully', 'success')
            return redirect(url_for('applications'))

        except mysql.connector.Error as e:
            flash('Error: ' + str(e), 'danger')

    else:
        return render_template('delete_application.html', application_id=application_id)
    
@app.route('/interviews/<int:interview_id>')
@login_required
def view_interview(interview_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch interview details using the provided interview_id
        cursor.execute("SELECT * FROM Interviews WHERE InterviewID = %s", (interview_id,))
        interview = cursor.fetchone()

        # Close the cursor and connection
        cursor.close()
        conn.close()

        # Render the template with interview details
        return render_template('interview_details.html', interview=interview)

    except Exception as e:
        return "Error: " + str(e)

@app.route('/edit_interview/<int:interview_id>', methods=['GET', 'POST'])
@login_required
def edit_interview(interview_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if request.method == 'POST':
            # Handle form submission for updating interview details
            new_interview_date = request.form.get('new_interview_date')
            new_performance_notes = request.form.get('new_performance_notes')

            # Update the interview details in the database
            cursor.execute("UPDATE Interviews SET InterviewDate = %s, PerformanceNotes = %s WHERE InterviewID = %s",
                           (new_interview_date, new_performance_notes, interview_id))
            conn.commit()

            # Redirect to the interview details page after editing
            return redirect(url_for('view_interview', interview_id=interview_id))

        else:
            # Fetch current interview details
            cursor.execute("SELECT * FROM Interviews WHERE InterviewID = %s", (interview_id,))
            interview = cursor.fetchone()

            # Render the template with the current interview details
            return render_template('edit_interview.html', interview=interview)

    except Exception as e:
        return "Error: " + str(e)

    finally:
        # Close the cursor and connection
        cursor.close()
        conn.close()

@app.route('/analysis')
@login_required
@admin_required
def analysis():

    return render_template('analysis.html') 

@app.route('/powerbi')
@login_required
@admin_required
def powerbi():
    
    return render_template('powerbi.html') 

@app.route('/d3js')
@login_required
@admin_required
def d3js():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Replace 'your_table' with the actual table name where applications are stored
        cursor.execute("SELECT ApplicationDate, COUNT(*) as Count FROM Applications GROUP BY ApplicationDate")
        application_counts = cursor.fetchall()
        print(application_counts)
        # Close the cursor and connection
        cursor.close()
        conn.close()

        return render_template('d3js.html', application_counts=application_counts)

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
    
    if request.method == 'POST':
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            delete_applications_query = "DELETE FROM Applications WHERE UserID = %s"
            cursor.execute(delete_applications_query, (user_id,))
            conn.commit()

            delete_dataprivacy_query = "DELETE FROM DataPrivacy WHERE UserID = %s"
            cursor.execute(delete_dataprivacy_query, (user_id,))
            conn.commit()

            # Delete the user from the database based on user_id
            delete_useraccount_query = "DELETE FROM UserAccount WHERE UserID = %s"
            cursor.execute(delete_useraccount_query, (user_id,))
            conn.commit()

            cursor.close()
            conn.close()

            flash('User deleted successfully', 'success')
            return redirect(url_for('manage_users'))  # Redirect to the user management page

        except mysql.connector.Error as e:
            flash('Error: ' + str(e), 'danger')

    else:
        return render_template('delete_user.html', user_id=user_id)  # Render the confirmation page


@app.route('/privacy_settings', methods=['GET', 'POST'])
@login_required
def privacy_settings():
    if request.method == 'POST':
        new_privacy_status = bool(int(request.form.get('is_private')))
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Use raw SQL with a cursor to either update or insert the privacy settings
            sql_statement = """
                INSERT INTO DataPrivacy (UserID, IsDataPrivate) VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE IsDataPrivate = %s
            """

            cursor.execute(
                sql_statement,
                (current_user.id, new_privacy_status, new_privacy_status)
            )
            
            conn.commit()
            flash('Privacy settings updated successfully!', 'success')

        except Exception as e:
            conn.rollback()
            flash(f'Error updating privacy settings: {str(e)}', 'danger')

        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('privacy_settings'))

    # Fetch the current user's privacy settings
    conn = get_db_connection()
    cursor = conn.cursor()

    privacy_settings = None

    try:
        cursor.execute("SELECT * FROM DataPrivacy WHERE UserID = %s", (current_user.id,))
        privacy_settings = cursor.fetchone()

    except Exception as e:
        flash(f'Error fetching privacy settings: {str(e)}', 'danger')

    finally:
        cursor.close()
        conn.close()

    return render_template('privacy_settings.html', privacy_settings=privacy_settings)


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
