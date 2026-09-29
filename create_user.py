import mysql.connector
from werkzeug.security import generate_password_hash


# Database connection
connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="spyguard"
)

cursor = connection.cursor()

# Admin account details
username = "admin"
email = "admin@spyguard.com"
password = "Admin@123"

# Create secure password hash
password_hash = generate_password_hash(password)

# Insert user
query = """
INSERT INTO users (username, email, password_hash, role)
VALUES (%s, %s, %s, %s)
"""

values = (username, email, password_hash, "admin")

cursor.execute(query, values)

connection.commit()

print("Admin user created successfully!")

cursor.close()
connection.close()