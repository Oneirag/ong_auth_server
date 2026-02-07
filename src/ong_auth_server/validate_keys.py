#!/usr/bin/env python3
"""
KeyValidator class for secure API key validation with SQLite database
Includes timing attack protection and secure password hashing
"""

import sqlite3
import hashlib
import hmac
import secrets
import time
import logging
from typing import Optional, Tuple
from pathlib import Path
from contextlib import contextmanager
from threading import Lock

from click import prompt


class KeyValidator:
    """
    Secure API key validator with SQLite database backend

    API key format: username{separator}password
    Default separator: '#'

    Features:
    - Timing attack protection
    - Secure password hashing with salt
    - Thread-safe operations
    - Automatic database initialization
    - User management (add/deactivate)
    """

    def __init__(self, db_path: str = "~/.config/ongpi/api_keys.db", separator: str = "#",
                 constant_time_delay: float = 0.1):
        """
        Initialize KeyValidator with SQLite database

        Args:
            db_path: Path to SQLite database file. Defaults to "~./config/ongpi/api_keys.db"
            separator: Character separating username and password in API key
            constant_time_delay: Minimum time for operations (timing attack protection)
        """
        self.db_path = Path(db_path).expanduser()
        self.separator = separator
        self.constant_time_delay = constant_time_delay
        self._db_lock = Lock()  # Thread safety

        # Setup logging
        self.logger = logging.getLogger(__name__)

        # Initialize database
        self._init_database()

    def _init_database(self) -> None:
        """Initialize SQLite database with required schema"""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()

                # Create users table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS api_users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        is_active INTEGER NOT NULL DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(username)
                    )
                """)

                # Create index for faster lookups
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_username_active 
                    ON api_users(username, is_active)
                """)

                # Create audit log table (optional, for security monitoring)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS auth_attempts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        success INTEGER NOT NULL,
                        ip_address TEXT,
                        user_agent TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # Create valid IPs table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS valid_ip (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL UNIQUE,
                        description TEXT,
                        is_active INTEGER NOT NULL DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # Create index for faster IP lookups
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_ip_active 
                    ON valid_ip(ip_address, is_active)
                """)

                conn.commit()
                self.logger.info(f"Database initialized at {self.db_path}")

        except sqlite3.Error as e:
            self.logger.error(f"Database initialization failed: {e}")
            raise

    @contextmanager
    def _get_db_connection(self):
        """Thread-safe database connection context manager"""
        with self._db_lock:
            conn = None
            try:
                conn = sqlite3.connect(
                    str(self.db_path),
                    timeout=30.0,  # 30 second timeout
                    check_same_thread=False
                )
                conn.row_factory = sqlite3.Row  # Enable dict-like access
                yield conn
            except sqlite3.Error as e:
                if conn:
                    conn.rollback()
                self.logger.error(f"Database error: {e}")
                raise
            finally:
                if conn:
                    conn.close()

    def _hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """
        Securely hash password with salt

        Args:
            password: Plain text password
            salt: Optional salt (generates new one if not provided)

        Returns:
            Tuple of (password_hash, salt)
        """
        if salt is None:
            salt = secrets.token_hex(32)  # 256-bit salt

        # Use PBKDF2 with SHA256 for password hashing
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # 100,000 iterations
        )

        return password_hash.hex(), salt

    def _constant_time_operation(self, operation_func, *args, **kwargs):
        """
        Execute operation with constant time delay for timing attack protection

        Args:
            operation_func: Function to execute
            *args, **kwargs: Arguments for the function

        Returns:
            Function result
        """
        start_time = time.time()
        result = operation_func(*args, **kwargs)

        # Ensure minimum time has elapsed
        elapsed_time = time.time() - start_time
        remaining_time = self.constant_time_delay - elapsed_time
        if remaining_time > 0:
            time.sleep(remaining_time)

        return result

    def _parse_api_key(self, api_key: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Parse API key into username and password

        Args:
            api_key: API key string

        Returns:
            Tuple of (username, password) or (None, None) if invalid
        """
        if not api_key or self.separator not in api_key:
            return None, None

        try:
            # Split only on first occurrence of separator
            parts = api_key.split(self.separator, 1)
            if len(parts) != 2:
                return None, None

            username, password = parts

            # Basic validation
            if not username or not password:
                return None, None

            # # Validate username format (alphanumeric + some special chars)
            # if not username.replace('_', '').replace('-', '').replace('.', '').isalnum():
            #     return None, None

            return username.strip(), password

        except Exception as e:
            self.logger.warning(f"API key parsing error: {e}")
            return None, None

    def _validate_credentials(self, username: str, password: str) -> bool:
        """
        Internal method to validate credentials against database

        Args:
            username: Username to validate
            password: Password to validate

        Returns:
            True if valid, False otherwise
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()

                # Query for active user
                cursor.execute("""
                    SELECT password_hash, salt 
                    FROM api_users 
                    WHERE username = ? AND is_active = 1
                """, (username,))

                result = cursor.fetchone()

                if result:
                    stored_hash = result['password_hash']
                    salt = result['salt']

                    # Hash the provided password with stored salt
                    calculated_hash, _ = self._hash_password(password, salt)

                    # Constant-time comparison
                    return hmac.compare_digest(stored_hash, calculated_hash)
                else:
                    # Perform dummy operation to maintain constant time
                    dummy_password = "dummy_password_for_timing"
                    self._hash_password(dummy_password, "dummy_salt")
                    return False

        except Exception as e:
            self.logger.error(f"Credential validation error: {e}")
            # Perform dummy operation on error to maintain timing
            self._hash_password("error_dummy", "error_salt")
            return False

    def validate_key(self, api_key: str, client_info: Optional[dict] = None) -> bool:
        """
        Validate API key with timing attack protection

        Args:
            api_key: API key to validate
            client_info: Optional client information for logging (ip, user_agent)

        Returns:
            True if valid, False otherwise
        """

        def _internal_validate():
            # Parse API key
            username, password = self._parse_api_key(api_key)

            if username is None or password is None:
                self._log_auth_attempt(None, False, client_info)
                return False

            # Validate credentials
            is_valid = self._validate_credentials(username, password)

            # Log attempt
            self._log_auth_attempt(username, is_valid, client_info)

            return is_valid

        # Execute with constant time protection
        return self._constant_time_operation(_internal_validate)

    def add_user(self, username: str, password: str) -> bool:
        """
        Add new user or update existing user's password

        Args:
            username: Username to add/update
            password: Plain text password

        Returns:
            True if successful, False otherwise
        """
        if not username or not password:
            self.logger.warning("Cannot add user: username or password is empty")
            return False

        # # Validate username format
        # if not username.replace('_', '').replace('-', '').replace('.', '').isalnum():
        #     self.logger.warning(f"Invalid username format: {username}")
        #     return False

        # Validate password strength
        if len(password) < 8:
            self.logger.warning("Password too short (minimum 8 characters)")
            return False

        try:
            # Hash password
            password_hash, salt = self._hash_password(password)

            with self._get_db_connection() as conn:
                cursor = conn.cursor()

                # First, deactivate any existing entries for this username
                cursor.execute("""
                    UPDATE api_users 
                    SET is_active = 0, updated_at = CURRENT_TIMESTAMP 
                    WHERE username = ?
                """, (username,))

                # Insert new active entry
                cursor.execute("""
                    INSERT INTO api_users (username, password_hash, salt, is_active)
                    VALUES (?, ?, ?, 1)
                """, (username, password_hash, salt))

                conn.commit()
                self.logger.info(f"User '{username}' added/updated successfully")
                return True

        except sqlite3.Error as e:
            self.logger.error(f"Failed to add user '{username}': {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error adding user '{username}': {e}")
            return False

    def deactivate_user(self, username: str) -> bool:
        """
        Deactivate a user (disable their API access)

        Args:
            username: Username to deactivate

        Returns:
            True if successful, False otherwise
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    UPDATE api_users 
                    SET is_active = 0, updated_at = CURRENT_TIMESTAMP 
                    WHERE username = ? AND is_active = 1
                """, (username,))

                if cursor.rowcount > 0:
                    conn.commit()
                    self.logger.info(f"User '{username}' deactivated successfully")
                    return True
                else:
                    self.logger.warning(f"User '{username}' not found or already inactive")
                    return False

        except sqlite3.Error as e:
            self.logger.error(f"Failed to deactivate user '{username}': {e}")
            return False

    def list_users(self, include_inactive: bool = False) -> list:
        """
        List all users in the database

        Args:
            include_inactive: Whether to include inactive users

        Returns:
            List of user dictionaries
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()

                if include_inactive:
                    cursor.execute("""
                        SELECT username, is_active, created_at, updated_at 
                        FROM api_users 
                        ORDER BY created_at DESC
                    """)
                else:
                    cursor.execute("""
                        SELECT username, is_active, created_at, updated_at 
                        FROM api_users 
                        WHERE is_active = 1 
                        ORDER BY created_at DESC
                    """)

                return [dict(row) for row in cursor.fetchall()]

        except sqlite3.Error as e:
            self.logger.error(f"Failed to list users: {e}")
            return []

    def add_valid_ip(self, ip_address: str, description: str = "") -> bool:
        """
        Add a valid IP address to the whitelist

        Args:
            ip_address: IP address to add
            description: Optional description for the IP

        Returns:
            True if successful, False otherwise
        """
        if not ip_address:
            self.logger.warning("Cannot add IP: ip_address is empty")
            return False

        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()

                # Check if IP already exists
                cursor.execute("""
                    SELECT id FROM valid_ip WHERE ip_address = ?
                """, (ip_address,))

                if cursor.fetchone():
                    # IP exists, update it to active
                    cursor.execute("""
                        UPDATE valid_ip 
                        SET is_active = 1, updated_at = CURRENT_TIMESTAMP, description = ?
                        WHERE ip_address = ?
                    """, (description, ip_address))
                else:
                    # Insert new IP
                    cursor.execute("""
                        INSERT INTO valid_ip (ip_address, description, is_active)
                        VALUES (?, ?, 1)
                    """, (ip_address, description))

                conn.commit()
                self.logger.info(f"Valid IP '{ip_address}' added successfully")
                return True

        except sqlite3.Error as e:
            self.logger.error(f"Failed to add valid IP '{ip_address}': {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error adding valid IP '{ip_address}': {e}")
            return False

    def is_valid_ip(self, ip_address: str) -> bool:
        """
        Check if an IP address is in the valid IP whitelist

        Args:
            ip_address: IP address to validate

        Returns:
            True if IP is valid/whitelisted, False otherwise
        """
        if not ip_address:
            self.logger.warning("Cannot validate IP: ip_address is empty")
            return False

        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT id FROM valid_ip 
                    WHERE ip_address = ? AND is_active = 1
                """, (ip_address,))

                result = cursor.fetchone()
                return result is not None

        except sqlite3.Error as e:
            self.logger.error(f"Failed to validate IP '{ip_address}': {e}")
            return False

    def remove_valid_ip(self, ip_address: str) -> bool:
        """
        Remove/deactivate a valid IP address

        Args:
            ip_address: IP address to remove

        Returns:
            True if successful, False otherwise
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    UPDATE valid_ip 
                    SET is_active = 0, updated_at = CURRENT_TIMESTAMP 
                    WHERE ip_address = ? AND is_active = 1
                """, (ip_address,))

                if cursor.rowcount > 0:
                    conn.commit()
                    self.logger.info(f"Valid IP '{ip_address}' removed successfully")
                    return True
                else:
                    self.logger.warning(f"Valid IP '{ip_address}' not found or already inactive")
                    return False

        except sqlite3.Error as e:
            self.logger.error(f"Failed to remove valid IP '{ip_address}': {e}")
            return False

    def list_valid_ips(self, include_inactive: bool = False) -> list:
        """
        List all valid IP addresses

        Args:
            include_inactive: Whether to include inactive IPs

        Returns:
            List of IP dictionaries
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()

                if include_inactive:
                    cursor.execute("""
                        SELECT ip_address, description, is_active, created_at, updated_at 
                        FROM valid_ip 
                        ORDER BY created_at DESC
                    """)
                else:
                    cursor.execute("""
                        SELECT ip_address, description, is_active, created_at, updated_at 
                        FROM valid_ip 
                        WHERE is_active = 1 
                        ORDER BY created_at DESC
                    """)

                return [dict(row) for row in cursor.fetchall()]

        except sqlite3.Error as e:
            self.logger.error(f"Failed to list valid IPs: {e}")
            return []

        """
        List all users in the database

        Args:
            include_inactive: Whether to include inactive users

        Returns:
            List of user dictionaries
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()

                if include_inactive:
                    cursor.execute("""
                        SELECT username, is_active, created_at, updated_at 
                        FROM api_users 
                        ORDER BY created_at DESC
                    """)
                else:
                    cursor.execute("""
                        SELECT username, is_active, created_at, updated_at 
                        FROM api_users 
                        WHERE is_active = 1 
                        ORDER BY created_at DESC
                    """)

                return [dict(row) for row in cursor.fetchall()]

        except sqlite3.Error as e:
            self.logger.error(f"Failed to list users: {e}")
            return []

    def _log_auth_attempt(self, username: Optional[str], success: bool,
                          client_info: Optional[dict] = None) -> None:
        """
        Log authentication attempt for security monitoring

        Args:
            username: Username that was attempted
            success: Whether the attempt was successful
            client_info: Optional client information
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()

                ip_address = client_info.get('ip') if client_info else None
                user_agent = client_info.get('user_agent') if client_info else None

                cursor.execute("""
                    INSERT INTO auth_attempts (username, success, ip_address, user_agent)
                    VALUES (?, ?, ?, ?)
                """, (username, 1 if success else 0, ip_address, user_agent))

                conn.commit()

        except sqlite3.Error as e:
            # Don't raise exception for logging failures
            self.logger.warning(f"Failed to log auth attempt: {e}")

    def get_auth_stats(self, username: Optional[str] = None,
                       hours: int = 24) -> dict:
        """
        Get authentication statistics

        Args:
            username: Optional username to filter by
            hours: Number of hours to look back

        Returns:
            Dictionary with authentication statistics
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()

                base_query = """
                    SELECT 
                        COUNT(*) as total_attempts,
                        SUM(success) as successful_attempts,
                        COUNT(DISTINCT ip_address) as unique_ips
                    FROM auth_attempts 
                    WHERE timestamp > datetime('now', '-{} hours')
                """.format(hours)

                if username:
                    base_query += " AND username = ?"
                    cursor.execute(base_query, (username,))
                else:
                    cursor.execute(base_query)

                result = cursor.fetchone()

                return {
                    'total_attempts': result['total_attempts'] or 0,
                    'successful_attempts': result['successful_attempts'] or 0,
                    'failed_attempts': (result['total_attempts'] or 0) - (result['successful_attempts'] or 0),
                    'unique_ips': result['unique_ips'] or 0,
                    'success_rate': (result['successful_attempts'] or 0) / max(result['total_attempts'] or 1, 1) * 100
                }

        except sqlite3.Error as e:
            self.logger.error(f"Failed to get auth stats: {e}")
            return {}


def add_users():
    user = prompt("Give me a user name:")
    password = prompt("Give me a password:")


# =============================================================================
# USAGE EXAMPLES
# =============================================================================

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Initialize validator
    validator = KeyValidator("test_auth_keys.db", separator="#")

    # Add some test users
    print("Adding test users...")
    validator.add_user("admin", "secure_password_123")
    validator.add_user("api_user", "another_secure_pass")
    validator.add_user("test_user", "test_password_456")

    validator.add_valid_ip("8.8.8.8", "Google DNS")

    # Test API keys
    test_keys = [
        "admin#secure_password_123",  # Valid
        "api_user#another_secure_pass",  # Valid
        "admin#wrong_password",  # Invalid password
        "nonexistent#password",  # Invalid user
        "invalid_format",  # Invalid format
        "",  # Empty key
    ]

    print("\nTesting API key validation:")
    for key in test_keys:
        is_valid = validator.validate_key(key)
        print(f"Key: '{key[:20]}...' - Valid: {is_valid}")

    # Test IP validation
    print("\nTesting IP validation:")
    test_ips = ["8.8.8.8", "192.168.1.1", "10.0.0.1"]
    for ip in test_ips:
        is_valid = validator.is_valid_ip(ip)
        print(f"IP: {ip} - Valid: {is_valid}")

    # Get auth stats
    print("\nAuthentication statistics:")
    stats = validator.get_auth_stats()
    print(f"Total attempts: {stats.get('total_attempts', 0)}")
    print(f"Successful: {stats.get('successful_attempts', 0)}")
    print(f"Failed: {stats.get('failed_attempts', 0)}")
    print(f"Success rate: {stats.get('success_rate', 0):.1f}%")