import hashlib
import os
from typing import Optional, Tuple
from dilithium_core import DilithiumCore
from ecdsa_core import ECDSACore   # вместо eddsa_core

class HybridKeyPair:
    def __init__(self, 
                 dilithium_core: Optional[DilithiumCore] = None,
                 ecdsa_core: Optional[ECDSACore] = None):
        self.dilithium = dilithium_core or DilithiumCore()
        self.ecdsa = ecdsa_core or ECDSACore()
        
        self.classical_private: Optional[bytes] = None
        self.classical_public: Optional[bytes] = None
        self.pqc_public: Optional[bytes] = None
        self.pqc_seed: Optional[bytes] = None
        self.address: Optional[str] = None

    def generate(self) -> "HybridKeyPair":
        """Генерирует гибридную ключевую пару (ECDSA + Dilithium)."""
        # 1. Генерация классической пары ECDSA через Rust
        self.classical_public, self.classical_private = self.ecdsa.generate()
        
        # 2. Генерация постквантовой пары Dilithium через Rust
        self.pqc_public, self.pqc_seed = self.dilithium.generate()
        
        # 3. Вычисление адреса
        self.address = self._generate_address()
        return self

    def _generate_address(self) -> str:
        if self.classical_public is None or self.pqc_public is None:
            raise ValueError("Ключи не инициализированы")
        
        combined = self.classical_public + self.pqc_public
        pub_hash = hashlib.sha256(combined).digest()
        version = b"\x01"
        algo_id = b"\x01\x01"  # ECDSA (secp256k1) + Dilithium (было b"\x02\x01" для Ed25519)
        checksum = hashlib.sha256(hashlib.sha256(version + algo_id + pub_hash).digest()).digest()[:4]
        address_bytes = version + algo_id + pub_hash + checksum
        return "0x" + address_bytes.hex()

    def save_to_file(self, directory: str = "./keys") -> None:
        """Сохраняет ключи в бинарные файлы."""
        os.makedirs(directory, exist_ok=True)
        
        with open(f"{directory}/ecdsa_private.bin", "wb") as f:
            f.write(self.classical_private)
        with open(f"{directory}/ecdsa_public.bin", "wb") as f:
            f.write(self.classical_public)
        with open(f"{directory}/dilithium_public.bin", "wb") as f:
            f.write(self.pqc_public)
        with open(f"{directory}/dilithium_seed.bin", "wb") as f:
            f.write(self.pqc_seed)
        with open(f"{directory}/address.txt", "w") as f:
            f.write(self.address)

    @classmethod
    def load_from_file(cls, directory: str = "./keys",
                       dilithium_core: Optional[DilithiumCore] = None,
                       ecdsa_core: Optional[ECDSACore] = None) -> "HybridKeyPair":
        """Загружает ключи из файлов."""
        hybrid = cls(dilithium_core, ecdsa_core)
        
        with open(f"{directory}/ecdsa_private.bin", "rb") as f:
            hybrid.classical_private = f.read()
        with open(f"{directory}/ecdsa_public.bin", "rb") as f:
            hybrid.classical_public = f.read()
        with open(f"{directory}/dilithium_public.bin", "rb") as f:
            hybrid.pqc_public = f.read()
        with open(f"{directory}/dilithium_seed.bin", "rb") as f:
            hybrid.pqc_seed = f.read()
        with open(f"{directory}/address.txt", "r") as f:
            hybrid.address = f.read().strip()
        
        return hybrid

    # Геттеры для безопасного доступа
    def get_classical_private_key(self) -> bytes:
        if self.classical_private is None:
            raise ValueError("Классический приватный ключ не инициализирован")
        return self.classical_private

    def get_classical_public_key(self) -> bytes:
        if self.classical_public is None:
            raise ValueError("Классический публичный ключ не инициализирован")
        return self.classical_public

    def get_pqc_public_key(self) -> bytes:
        if self.pqc_public is None:
            raise ValueError("Постквантовый публичный ключ не инициализирован")
        return self.pqc_public

    def get_pqc_seed(self) -> bytes:
        if self.pqc_seed is None:
            raise ValueError("Постквантовый сид не инициализирован")
        return self.pqc_seed