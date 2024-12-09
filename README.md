Features:
User Registration: Users can register by providing a username and email. Passwords are securely generated and hashed using Argon2.
JWT Authentication: The server generates JSON Web Tokens (JWT) with claims like user information and expiration time. It utilizes RSA keys for signing and verification.
Rate Limiting: Limits the number of authentication requests per second to prevent brute-force attacks.
Key Management: Stores private keys securely in an SQLite database with expiration times.
Public Key Exposure: Exposes public keys through the /well-known/jwks.json endpoint for client verification.
Usage:
Configuration:
  Set the NOT_MY_KEY environment variable with your actual encryption key.
  Ensure the database.py module defines the create_tables function for database setup.
Running the Server:
  Execute python server.py
User Registration:
  Send a POST request to /register with a JSON body containing username and email.
Authentication:
  Send a POST request to /auth with optional expired parameter to request an expired token for testing purposes.
  The response will contain a JWT token or an error message.
Public Key Retrieval:
  Send a GET request to /.well-known/jwks.json to retrieve the public key for verification.

  I utilized Microsoft's Copilot AI for this project. I input my code and piece by piece implemented the instructions by trying its suggestions. When something didn't work I'd put it back in and ask it to fix based on what error I was recieving. 
  I also wrote the test suite with Copilot. Project 3 was done completely using AI. I could not figure out why the auth requests weren't logging. 
