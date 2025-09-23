import os
import json
from cryptography.fernet import Fernet

class SessionStore:
    def __init__(self, instance_path):
        self.instance_path = instance_path
        self.credentials_path = os.path.join(instance_path, 'credentials')
        self.key_path = os.path.join(instance_path, 'credentials.key')
        os.makedirs(instance_path, exist_ok=True)
        self.fernet = self._get_fernet()

    def _generate_key(self):
        key = Fernet.generate_key()
        with open(self.key_path, 'wb') as f:
            f.write(key)
        return key

    def _get_fernet(self):
        if not os.path.exists(self.key_path):
            key = self._generate_key()
        else:
            with open(self.key_path, 'rb') as f:
                key = f.read()
        return Fernet(key)

    def save_credentials(self, credentials):
        encrypted_data = self.fernet.encrypt(json.dumps(credentials).encode())
        with open(self.credentials_path, 'wb') as f:
            f.write(encrypted_data)

    def load_credentials(self):
        if not os.path.exists(self.credentials_path):
            return {}
        try:
            with open(self.credentials_path, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data)
        except Exception as e:
            print(f"Error loading credentials: {e}")
            return {}

    def store_user_session(self, user_id, username, role, password):
        credentials = self.load_credentials()
        credentials[str(user_id)] = {
            'username': username,
            'role': role,
            'password': password
        }
        self.save_credentials(credentials)

    def get_user_session(self, user_id):
        credentials = self.load_credentials()
        return credentials.get(str(user_id))

    def clear_user_session(self, user_id):
        credentials = self.load_credentials()
        if str(user_id) in credentials:
            del credentials[str(user_id)]
            self.save_credentials(credentials)
