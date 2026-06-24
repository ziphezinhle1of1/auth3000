"""
cli.py — Interactive front-end for the authentication engine in auth.py

Run it with:  python3 cli.py

This is just a thin terminal UI. All the security logic lives in auth.py.
"""

from getpass import getpass

from auth import AuthService, AuthError, PasswordPolicyError, MIN_PASSWORD_LENGTH


def main() -> None:
    svc = AuthService("users.json")
    session_token = None  # the logged-in user's session, if any

    menu = """
=== Authentication Demo ===
  1. Register
  2. Log in
  3. Who am I? (check session)
  4. Enable MFA (TOTP)
  5. Log out
  6. Quit
"""
    while True:
        print(menu)
        choice = input("Choose an option: ").strip()

        # ---- Register --------------------------------------------------- #
        if choice == "1":
            username = input("Username: ")
            print(f"(Password needs >= {MIN_PASSWORD_LENGTH} chars, a letter and a digit.)")
            password = getpass("Password: ")
            try:
                svc.register(username, password)
                print(f"✓ Registered '{username.strip().lower()}'. You can now log in.")
            except (AuthError, PasswordPolicyError) as e:
                print(f"✗ {e}")

        # ---- Log in ----------------------------------------------------- #
        elif choice == "2":
            username = input("Username: ")
            password = getpass("Password: ")
            totp = None
            user = svc.users.get(username.strip().lower())
            if user and user.mfa_enabled:
                totp = input("6-digit MFA code: ").strip()
            try:
                session_token = svc.authenticate(username, password, totp_code=totp)
                print(f"✓ Logged in. Session token (keep this secret): {session_token}")
            except AuthError as e:
                print(f"✗ {e}")

        # ---- Who am I --------------------------------------------------- #
        elif choice == "3":
            if not session_token:
                print("No active session.")
            else:
                who = svc.whoami(session_token)
                print(f"You are logged in as: {who}" if who else "Session expired or invalid.")

        # ---- Enable MFA ------------------------------------------------- #
        elif choice == "4":
            who = svc.whoami(session_token) if session_token else None
            if not who:
                print("✗ Log in first before enabling MFA.")
            else:
                uri = svc.enable_mfa(who)
                print("\n✓ MFA enabled. Add this to your authenticator app.")
                print(f"  otpauth URI: {uri}")
                # If you want a scannable QR in the terminal: pip install qrcode
                try:
                    import qrcode
                    qr = qrcode.QRCode()
                    qr.add_data(uri)
                    qr.print_ascii(invert=True)
                except ImportError:
                    print("  (Install 'qrcode' to render a scannable QR code here.)")

        # ---- Log out ---------------------------------------------------- #
        elif choice == "5":
            if session_token:
                svc.logout(session_token)
                session_token = None
                print("✓ Logged out; session invalidated.")
            else:
                print("No active session.")

        # ---- Quit ------------------------------------------------------- #
        elif choice == "6":
            print("Bye.")
            break

        else:
            print("Unknown option.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nBye.")
