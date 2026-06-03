import os
from typing import Tuple
from eth_account import Account
from eth_keys import keys
from eth_utils import keccak

class ECDSACore:
    def generate(self) -> Tuple[bytes, bytes]:
        account = Account.create()
        private_key = account.key  # bytes, 32 байта
        private_key_obj = keys.PrivateKey(private_key)
        public_key = private_key_obj.public_key.to_bytes()  # 64 байта
        return public_key, private_key

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        private_key_obj = keys.PrivateKey(private_key)
        message_hash = keccak(message)
        signature = private_key_obj.sign_msg_hash(message_hash)
        return signature.to_bytes()

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            public_key_obj = keys.PublicKey.from_bytes(public_key)
            message_hash = keccak(message)
            return public_key_obj.verify_msg_hash(message_hash, signature)
        except Exception:
            return False