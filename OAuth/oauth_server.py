#192.168.1.3
import socket
import json
import jwt
import datetime

# Secret key for JWT signing (keep this secret!)
SECRET_KEY = b'MTFsz1olvMkBcJbW2HMtkF98x3MeY2JO2Mh8ZhATX3E='

def oauth_provider():
    oauth_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 8081) # listening for the auth server

    oauth_socket.bind(server_address)
    oauth_socket.listen(1)

    print("OAuth provider is waiting for a connection from the authentication server...")
    auth_connection, auth_address = oauth_socket.accept()

    print(f"Accepted connection")
    data = auth_connection.recv(1024).decode()
    username, password = data.split(":")

    # Real OAuth token generation
    oauth_token = generate_oauth_token(username)

    print(f"OAuth provider: Generated OAuth token: {oauth_token}")

    # JSON Response
    auth_response = {
        "auth": "success",
        "token": oauth_token
    }

    # Convert the JSON response to a string
    json_response = json.dumps(auth_response)

    # Send the JSON token to the authentication server
    print("SENDING JSON TOKEN:", json_response)
    auth_connection.send(json_response.encode()) # send this back to the auth server

    print("Sent successfully")

def generate_oauth_token(username):
    # Generate a JWT token with user-specific data
    payload = {
        "sub": username,  # Subject (usually the user)
        "iat": datetime.datetime.utcnow(),  # Issued at time
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)  # Token expiration time
    }

    oauth_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return oauth_token

if __name__ == "__main__":
    oauth_provider()
