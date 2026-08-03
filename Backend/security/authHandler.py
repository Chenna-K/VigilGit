import jwt
import os 
from dotenv import load_dotenv
import time

load_dotenv("../.env")

JWT_SECRET = os.getenv("JWT_SECRET")
jwt_algorithm = os.getenv("JWT_ALGORITHM")

class AuthHandler(object):

    @staticmethod
    def sign_jwt(user_id : int) -> str:
        payload = {
            "user_id" : user_id,
            "expires": time.time() + 600 
        }

        token = jwt.encode(payload, JWT_SECRET, algorithm=jwt_algorithm)
        return token
    @staticmethod
    def decode_jwt(token : str) -> dict:
        try:
            decoded_token = jwt.decode(token, JWT_SECRET, algorithms=jwt_algorithm)
            return decoded_token if decoded_token["expires"] >= time.time() else None
        except:
            return None