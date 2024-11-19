Multi-Server OAuth Authentication System used for educational purposes

This repository contains an implementation of a multi-server OAuth-based authentication system. It demonstrates 'secure' communication and token-based authentication between a client, an OAuth provider, and an application server.

**Features**
Client: Sends user credentials to the authentication server and forwards the OAuth token to the application server.
OAuth Provider: Issues secure JSON Web Tokens (JWTs) for authenticated users.
Application Server: Verifies the authenticity of the OAuth token and grants access accordingly.

**Architecture Overview**
Client:
Sends user credentials to the authentication server.
Receives an encrypted OAuth token upon successful authentication.
Forwards the token to the application server.

**OAuth Provider:**
Validates user credentials.
Generates a JWT for authenticated users, signed with a secret key.

**Application Server:**
Decrypts and validates the OAuth token to verify the client’s identity.

**Project Structure**
client.py: Handles user credential input and interacts with the authentication server and application server.
oauth_server.py: Generates and issues secure JWT tokens.
application_server.py: Validates the JWT token and processes client requests.
Prerequisites
Python 3.8+
Required libraries:
cryptography
pyjwt
Install dependencies using pip:

bash
Copy code
pip install cryptography pyjwt
Getting Started
Run the OAuth Provider:

bash
Copy code
python oauth_server.py
Run the Application Server:

bash
Copy code
python application_server.py
Run the Client:

bash
Copy code
python client.py
Enter your username and password in the client terminal when prompted.

**Security Considerations**
Ensure the SECRET_KEY is kept confidential and not hardcoded in production environments.
Use proper encryption protocols (e.g., TLS) for socket communication in real-world applications.
Passwords should be hashed and stored securely on the server.
Known Issues
Error handling for invalid tokens and network failures is minimal.
Authentication server functionality is integrated with the OAuth provider for simplicity.
License
This project is licensed under the MIT License. See the LICENSE file for details.
