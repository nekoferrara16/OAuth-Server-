#192.168.1.2
import base64
import hashlib
import json
import socket
from cryptography.fernet import Fernet
# Auth server

# Receives log in creds from client and compares them to the username and password down below
# sends https request to oauth provider

# . If the credentials are not valid, the OAUTH provider will not return an OAUTH token to the
# authentication server and the authentication server should return the following JSON to the
# client, indicating an unsuccessful login: {“auth”:”fail”, “token”:””}
SECRET_KEY = "MTFsz1olvMkBcJbW2HMtkF98x3MeY2JO2Mh8ZhATX3E="
def authentication_server():
    auth_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 8080)  # Listening info for client

    auth_socket.bind(server_address)
    auth_socket.listen(1)  # Listen for the client

    print("Authentication server is waiting for a connection...")
    client_connection, client_address = auth_socket.accept()

    print(f"Accepted connection")

    data = client_connection.recv(1024).decode()

    username, password = data.split(":")

    # Simulated authentication logic
    if username == "neko" and password == "password":

        print("Authentication server: Successful login")
        # Forward credentials to OAuth provider
        auth_socket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server1_address = ('192.168.1.3', 8081)  # IP OF OAUTH PROVIDER

        auth_socket1.connect(server1_address)

        data = f"{username}:{password}"
        auth_socket1.send(data.encode())  # send credentials

        #receive the token from the oauth server
        token = auth_socket1.recv(1024).decode()

        key = Fernet(SECRET_KEY)

        #encrypt json token from o auth server with key now

        enc_token = key.encrypt(token.encode())

        enc_json = "{'auth': Success, 'token': " + str(enc_token) + "}"

        # hash the encrypted json with the users password
        password_hash = hashlib.sha256(password.encode()).digest()  # PASSWORD HASH
        enc_pass = Fernet(base64.urlsafe_b64encode(password_hash[:64]))  # ENCRYPTING PASSWORD

        enc_response = enc_pass.encrypt(json.dumps(enc_json).encode())  # ENCRPYTING THE JSON WITH THE PASSWORD

        client_connection.send(enc_response)




    else:
        failed_login = "{'auth': fail, 'token': ''}"  # send this back to the client
        client_connection.send(failed_login.encode())




if __name__ == "__main__":
    authentication_server()