#192.168.1.1
import socket
import hashlib
import base64
import json
from cryptography.fernet import Fernet
# client sends creds to auth server

# 9. The client will decrypt the response sent to it from the authentication server and send the
# encrypted JSON containing the OAUTH token to the application server.
# 10. The application server will decrypt the encrypted JSON response containing the token using
# its secret key, indicating that the token came from the authentication server

PASS_FOR_DEC = ""
def send_creds(username, password):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    authserver_address = ('192.168.1.2', 8080)
    appserver_address = ('192.168.1.4', 8083)

    try:
        client_socket.connect(authserver_address)

        # Send credentials to the authentication server
        data = f"{username}:{password}"
        client_socket.send(data.encode())
        #receive token/failed login attempt
        result = client_socket.recv(1024).decode()

        #decrypt the response using the password provided
        password_hash = hashlib.sha256(password.encode()).digest()  # PASSWORD HASH
        key = Fernet(base64.urlsafe_b64encode(password_hash[:64]))  # ENCRYPTING PASSWORD

        raw_string = key.decrypt(json.dumps(result))

        dec_response = raw_string.decode('utf-8')

        print(dec_response)

        # send dec to app server

        app_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM ) # initializing to app server
        app_client_socket.connect(appserver_address)

        app_client_socket.send(raw_string)


    finally:
        client_socket.close()

if __name__ == "__main__":
    username = input("Enter the username: ")
    password = input("Enter the password: ")
    PASS_FOR_DEC = password
    send_creds(username, password)
