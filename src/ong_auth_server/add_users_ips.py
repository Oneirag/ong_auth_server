from validate_keys import KeyValidator

if __name__ == "__main__":
    # Initialize validator
    validator = KeyValidator()

    # list users and valid IPs
    print("Current users:")
    for user in validator.list_users():
        print(f" - {user}")
    print("\nCurrent valid IPs:")
    for ip in validator.list_valid_ips():
        print(f" - {ip}")

    # Add some test users
    print("Adding test users...")
    while True:
        username = input("Enter username (or 'done' to finish): ")
        if username.lower() == "done":
            break
        password = input(f"Enter password for {username}: ")
        validator.add_user(username, password)
        print(f"User '{username}' added successfully.")
    # Add a valid IP address, until empty string is added, all IPs will be considered invalid
    while True:
        ip = input("Enter valid IP address (or 'done' to finish): ")
        if ip.lower() == "done":
            break
        validator.add_valid_ip(ip)
        print(f"IP '{ip}' added successfully.")
    