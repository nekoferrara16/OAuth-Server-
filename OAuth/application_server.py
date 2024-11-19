#192.168.1.4
from cryptography.fernet import Fernet
import socket
import json

SECRET_KEY = "MTFsz1olvMkBcJbW2HMtkF98x3MeY2JO2Mh8ZhATX3E="

def application_server():
    application_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 8083)

    application_socket.bind(server_address)
    application_socket.listen(1)  # Listen for a single client connection

    print("Application server is waiting for a connection...")
    client_connection, client_address = application_socket.accept()

    print(f"Accepted connection")

    data = client_connection.recv(1024).decode()

    # Parse the JSON response containing the encrypted token and then decrypt the token
    response = json.loads(data)
    split = response.split(": b")
    split = split[1]
    cleaned_string = split.strip("'}'") # string of token
    if "token" in response:
        key = Fernet(SECRET_KEY)


        try:

            decrypted_token = key.decrypt(cleaned_string.encode()).decode()

            print(f"Decrypted token: {decrypted_token}")
        except Exception as e:
            print(f"Token decryption failed {e}")

if __name__ == "__main__":
    application_server()