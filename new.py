import bcrypt

# Example plain password
plain_password = "password123"

# Hashing the password
hashed_password = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt())

# Printing the hashed password
print("Hashed password:", hashed_password)

# Verifying the password
entered_password = "password123"
if bcrypt.checkpw(entered_password.encode("utf-8"), hashed_password):
    print("Password matched!")
else:
    print("Password did not match.")