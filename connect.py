import mysql.connector
import os
from dotenv import load_dotenv #pip install python-dotenv

load_dotenv()

# RDS database credentials
db_host = os.getenv("db_host")
db_port = os.getenv("db_port")
db_user = os.getenv("db_user")
db_password = os.getenv("db_password")
db_name = os.getenv("db_name")

# Function to establish a database connection
def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database=db_name
        )
        print("Connected to the database")

        return conn  # Return the connection object

    except mysql.connector.Error as e:
        print("Error:", e)
        return None  # Return None to indicate a failed connection

if __name__ == '__main__':
    get_db_connection()