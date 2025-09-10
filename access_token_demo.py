# simple Python stub that demonstrates how access tokens are typically used in an authentication flow. 
# This example uses a mock token generation and validation process
#
# steps:
#   Authenticates a user with a username and password.
#   Generates an access token if authentication is successful.
#   Stores the token with an expiration time.
#   Validates the token on subsequent requests to access protected resources.
#   Handles expired or invalid tokens.

import time
import uuid

# Simulate a database of users
USERS_DB = {
    "testUser1": "password123",
    "testUser2": "securepass"
}

# Simulated token store (in-memory)
TOKENS = {}

def authenticate(username, password):
    if USERS_DB.get(username) == password:
        token = str(uuid.uuid4())
        # Token expires in 60 seconds
        TOKENS[token] = {"username": username, "expires_at": time.time() + 60}
        return token
    return None

def validate_token(token):
    token_info = TOKENS.get(token)
    if not token_info:
        return False
    if time.time() > token_info["expires_at"]:
        # Token expired
        del TOKENS[token]
        return False
    return True

def access_protected_resource(token):
    if validate_token(token):
        username = TOKENS[token]["username"]
        return f"Welcome, {username}! You have accessed a protected resource."
    else:
        return "Access denied. Invalid or expired token."

# Example usage
if __name__ == "__main__":
    token = authenticate("testUser1", "password123")
    if token:
        print("Access token:", token)
        print(access_protected_resource(token))
        time.sleep(2)
        print(access_protected_resource(token))
    else:
        print("Authentication failed.")
