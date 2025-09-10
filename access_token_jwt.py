# Access token generated using jwt libary in python
#
# token is a JWT string, with username and expiration (exp) in the payload.
# we can replace SECRET_KEY with a secure key for production.

import time
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

# Simulate a database of users
USERS_DB = {
    "alice": "password123",
    "bob": "securepass"
}

# Secret key for JWT encoding/decoding
SECRET_KEY = "your-secret-key"
TOKEN_TIMEOUT = 60

def authenticate(username, password):
    """Authenticate user and return a JWT access token if successful."""
    if USERS_DB.get(username) == password:
        payload = {
            "username": username,
            "exp": time.time() + TOKEN_TIMEOUT
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return token
    return None

def validate_token(token):
    """Validate the JWT access token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return True, payload["username"]
    except ExpiredSignatureError:
        print("Token expired.")
        return False, None
    except InvalidTokenError:
        print("Invalid token.")
        return False, None

def access_protected_resource(token):
    """Simulate accessing a protected resource."""
    valid, username = validate_token(token)
    if valid:
        return f"Welcome, {username}! You have accessed a protected resource."
    else:
        return "Access denied. Invalid or expired token."

# Example usage
if __name__ == "__main__":
    token = authenticate("alice", "password123")
    if token:
        print("Access token (JWT):", token)
        print(access_protected_resource(token))
        time.sleep(2)
        print(access_protected_resource(token))
    else:
        print("Authentication failed.")
