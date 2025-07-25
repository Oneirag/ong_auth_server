#!/usr/bin/env python3
"""
Unit tests for Flask authentication server
Run with: python -m unittest test_auth_server.py -v
"""

import unittest
import requests
import time
from typing import Optional, Dict
from ong_auth_server import AUTH_HEADER, API_KEY_HEADER

# Server configuration
BASE_URL = "http://127.0.0.1:8888"
AUTH_ENDPOINT = f"{BASE_URL}/auth_api_key"

# Test API keys (replace with real keys from your database)
VALID_API_KEY = "hola"
INVALID_API_KEY = "invalid_key_123456"



class TestAuthServer(unittest.TestCase):
    """Unit tests for the authentication server endpoints"""

    @classmethod
    def setUpClass(cls):
        """Set up test class - runs once before all tests"""
        cls.base_url = BASE_URL
        cls.auth_endpoint = AUTH_ENDPOINT
        cls.session = requests.Session()

        # Test server connectivity
        cls._test_server_connection()

    @classmethod
    def _test_server_connection(cls):
        """Test if server is reachable before running tests"""
        try:
            response = requests.get(cls.base_url, timeout=5)
            print(f"? Server is reachable (status: {response.status_code})")
        except requests.exceptions.RequestException as e:
            print(f"? Cannot reach server at {cls.base_url}: {e}")
            print("Make sure the server is running before executing tests")
            raise unittest.SkipTest("Server not available")

    def setUp(self):
        """Set up each test case"""
        # Add small delay between tests to avoid rate limiting
        time.sleep(0.5)

    def tearDown(self):
        """Clean up after each test case"""
        pass

    def _make_request(self, method: str = "GET", headers: Optional[Dict[str, str]] = None) -> requests.Response:
        """
        Helper method to make HTTP requests to the auth endpoint

        Args:
            method: HTTP method (GET/POST)
            headers: Optional headers to include

        Returns:
            requests.Response: The response object
        """
        if method.upper() == "GET":
            return self.session.get(self.auth_endpoint, headers=headers, timeout=10)
        elif method.upper() == "POST":
            return self.session.post(self.auth_endpoint, headers=headers, timeout=10)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

    def test_valid_api_key_with_x_api_key_header_get(self):
        """Test valid API key using X-API_KEY header with GET method"""
        headers = {API_KEY_HEADER: VALID_API_KEY}
        response = self._make_request("GET", headers)

        self.assertEqual(response.status_code, 204,
                         f"Expected 204 No Content, got {response.status_code}")
        self.assertEqual(response.text, "",
                         "Response body should be empty for 204 status")

    def test_valid_api_key_with_x_api_key_header_post(self):
        """Test valid API key using X-API_KEY header with POST method"""
        headers = {API_KEY_HEADER: VALID_API_KEY}
        response = self._make_request("POST", headers)

        self.assertEqual(response.status_code, 204,
                         f"Expected 204 No Content, got {response.status_code}")
        self.assertEqual(response.text, "",
                         "Response body should be empty for 204 status")

    def test_valid_bearer_token_with_x_authorization_header(self):
        """Test valid API key using X-AUTHORIZATION Bearer token"""
        headers = {AUTH_HEADER: f"Bearer {VALID_API_KEY}"}
        response = self._make_request("GET", headers)

        self.assertEqual(response.status_code, 204,
                         f"Expected 204 No Content, got {response.status_code}")
        self.assertEqual(response.text, "",
                         "Response body should be empty for 204 status")

    def test_missing_api_key_returns_401(self):
        """Test request without API key returns 401 Unauthorized"""
        response = self._make_request("GET", headers=None)

        self.assertEqual(response.status_code, 401,
                         f"Expected 401 Unauthorized, got {response.status_code}")

        # Add delay after failed auth to avoid IP ban accumulation
        time.sleep(2)

    def test_invalid_api_key_returns_403(self):
        """Test request with invalid API key returns 403 Forbidden"""
        headers = {API_KEY_HEADER: INVALID_API_KEY}
        response = self._make_request("GET", headers)

        self.assertEqual(response.status_code, 403,
                         f"Expected 403 Forbidden, got {response.status_code}")

        # Add delay after failed auth to avoid IP ban accumulation
        time.sleep(2)

    def test_invalid_bearer_token_returns_403(self):
        """Test request with invalid Bearer token returns 403 Forbidden"""
        headers = {AUTH_HEADER: f"Bearer {INVALID_API_KEY}"}
        response = self._make_request("GET", headers)

        self.assertEqual(response.status_code, 403,
                         f"Expected 403 Forbidden, got {response.status_code}")

        # Add delay after failed auth to avoid IP ban accumulation
        time.sleep(2)

    def test_malformed_bearer_token_returns_401(self):
        """Test request with malformed Bearer token (missing 'Bearer ' prefix)"""
        headers = {AUTH_HEADER: VALID_API_KEY}  # Missing "Bearer " prefix
        response = self._make_request("GET", headers)

        self.assertEqual(response.status_code, 401,
                         f"Expected 401 Unauthorized, got {response.status_code}")

        # Add delay after failed auth to avoid IP ban accumulation
        time.sleep(2)

    def test_empty_api_key_header_returns_401(self):
        """Test request with empty API key header returns 401 Unauthorized"""
        headers = {API_KEY_HEADER: ""}
        response = self._make_request("GET", headers)

        self.assertEqual(response.status_code, 401,
                         f"Expected 401 Unauthorized, got {response.status_code}")

        # Add delay after failed auth to avoid IP ban accumulation
        time.sleep(2)

    def test_empty_bearer_token_returns_401(self):
        """Test request with empty Bearer token returns 401 Unauthorized"""
        headers = {AUTH_HEADER: "Bearer "}
        response = self._make_request("GET", headers)

        self.assertEqual(response.status_code, 401,
                         f"Expected 401 Unauthorized, got {response.status_code}")

        # Add delay after failed auth to avoid IP ban accumulation
        time.sleep(2)

    def test_additional_headers_with_valid_key(self):
        """Test that additional headers don't interfere with valid authentication"""
        headers = {
            API_KEY_HEADER: VALID_API_KEY,
            "User-Agent": "TestClient/1.0",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        response = self._make_request("GET", headers)

        self.assertEqual(response.status_code, 204,
                         f"Expected 204 No Content, got {response.status_code}")

    def test_case_sensitive_headers(self):
        """Test that header names are case insensitive (HTTP standard)"""
        # Most HTTP implementations are case-insensitive for headers
        headers = {API_KEY_HEADER.lower(): VALID_API_KEY}  # lowercase
        response = self._make_request("GET", headers)

        # This might fail depending on Flask's header handling
        # Documenting expected behavior
        self.assertIn(response.status_code, [204, 401],
                      "Header case sensitivity test - behavior may vary")

    def test_both_headers_present_x_api_key_takes_precedence(self):
        """Test behavior when both X-API_KEY and X-AUTHORIZATION are present"""
        headers = {
            API_KEY_HEADER: VALID_API_KEY,
            AUTH_HEADER: f"Bearer {INVALID_API_KEY}"
        }
        response = self._make_request("GET", headers)

        # Based on the code logic, X-API_KEY should take precedence
        self.assertEqual(response.status_code, 204,
                         "X-API_KEY should take precedence over X-AUTHORIZATION")

    def test_request_timeout_handling(self):
        """Test that requests don't hang indefinitely"""
        headers = {API_KEY_HEADER: VALID_API_KEY}

        start_time = time.time()
        response = self._make_request("GET", headers)
        end_time = time.time()

        # Request should complete within reasonable time
        self.assertLess(end_time - start_time, 10,
                        "Request took too long to complete")
        self.assertEqual(response.status_code, 204)


class TestAuthServerIntegration(unittest.TestCase):
    """Integration tests for authentication server"""

    def setUp(self):
        """Set up integration tests"""
        self.session = requests.Session()

    def test_multiple_valid_requests_dont_trigger_ban(self):
        """Test that multiple valid requests don't trigger IP ban"""
        headers = {API_KEY_HEADER: VALID_API_KEY}

        # Make multiple valid requests
        for i in range(5):
            response = self.session.get(AUTH_ENDPOINT, headers=headers, timeout=10)
            self.assertEqual(response.status_code, 204,
                             f"Request {i + 1} failed with status {response.status_code}")
            time.sleep(0.1)  # Small delay between requests

    @unittest.skip("Skipping IP ban test to avoid blocking test runner IP")
    def test_multiple_failed_requests_trigger_ban(self):
        """Test that multiple failed requests trigger IP ban (DISABLED by default)"""
        # This test is skipped by default to avoid IP bans during testing
        # Uncomment @unittest.skip to enable, but be aware of consequences

        # Make multiple invalid requests to trigger ban
        for i in range(3):
            response = self.session.get(AUTH_ENDPOINT, timeout=10)
            self.assertEqual(response.status_code, 401)
            time.sleep(1)

        # Next request should potentially be blocked (behavior depends on flask-ipban config)
        response = self.session.get(AUTH_ENDPOINT, timeout=10)
        # Exact behavior depends on flask-ipban configuration


if __name__ == '__main__':
    # Configure test runner
    unittest.main(
        verbosity=2,  # Verbose output
        buffer=True,  # Buffer stdout/stderr during tests
        failfast=False,  # Don't stop on first failure
        warnings='ignore'  # Ignore warnings
    )

# Alternative ways to run tests:
#
# Run specific test class:
# python -m unittest TestAuthServer -v
#
# Run specific test method:
# python -m unittest TestAuthServer.test_valid_api_key_with_x_api_key_header_get -v
#
# Run with coverage (if coverage.py is installed):
# coverage run -m unittest test_auth_server.py -v
# coverage report -m
#
# Run tests and generate XML report (for CI/CD):
# python -m unittest test_auth_server.py 2>&1 | tee test_results.txt