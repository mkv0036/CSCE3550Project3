import unittest
import requests
import json
import time
from http.server import HTTPServer
from threading import Thread
from main import MyServer, HOST_NAME, SERVER_PORT  # Ensure your server implementation is in main.py

class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start the server in a separate thread
        cls.server = HTTPServer((HOST_NAME, SERVER_PORT), MyServer)
        cls.server_thread = Thread(target=cls.server.serve_forever)
        cls.server_thread.setDaemon(True)
        cls.server_thread.start()
        time.sleep(1)  # Give the server time to start

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_register_user(self):
        url = f'http://{HOST_NAME}:{SERVER_PORT}/register'
        data = {
            "username": "test_user",
            "email": "test_user@example.com"
        }
        response = requests.post(url, json=data)
        self.assertEqual(response.status_code, 201)
        self.assertIn("password", response.json())

    def test_register_duplicate_user(self):
        url = f'http://{HOST_NAME}:{SERVER_PORT}/register'
        data = {
            "username": "test_user",
            "email": "test_user@example.com"
        }
        # First registration
        requests.post(url, json=data)
        # Duplicate registration
        response = requests.post(url, json=data)
        self.assertEqual(response.status_code, 409)
        self.assertIn("error", response.json())

    def test_authenticate_user(self):
        url = f'http://{HOST_NAME}:{SERVER_PORT}/auth'
        response = requests.post(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", response.json())

    def test_rate_limiting(self):
        url = f'http://{HOST_NAME}:{SERVER_PORT}/auth'
        for _ in range(10):
            response = requests.post(url)
        # 11th request should be rate-limited
        response = requests.post(url)
        self.assertEqual(response.status_code, 429)
        self.assertIn("error", response.json())



if __name__ == '__main__':
    unittest.main()
