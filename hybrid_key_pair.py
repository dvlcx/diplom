import hashlib
import os
from typing import Optional

import oqs
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey


class HybridKeyPair:
    """Класс для управления гибридной ключевой парой (Ed25519 + ML-DSA-65)."""

    def __init__(self):
        self.classical_private: Optional[EccKey] = None
        self.classical_public: Optional[EccKey] = None
        self.pqc_private: Optional[bytes] = None
        self.pqc_public: Optional[bytes] = None
        self.address: Optional[str] = None

    def generate(self) -> "HybridKeyPair":
        """Генерирует новую гибридную ключевую пару."""
        # 1. Генерация классической пары Ed25519 через PyCryptodome
        self.classical_private = ECC.generate(curve="ed25519")
        self.classical_public = self.classical_private.public_key()

        # 2. Генерация постквантовой пары ML-DSA-65 через liboqs
        # "Dilithium3" в liboqs соответствует ML-DSA-65 (NIST уровень 3)
        dilithium = oqs.Signature("Dilithium3")
        self.pqc_public = dilithium.generate_keypair()
        self.pqc_private = dilithium.export_secret_key()
        dilithium.free()

        # 3. Генерация адреса на основе публичных ключей
        self.address = self._generate_address()

        return self

    def _generate_address(self) -> str:
        if self.classical_public is None or self.pqc_public is None:
            raise ValueError("Ключи не инициализированы. Вызовите generate() сначала.")

        # Сериализуем публичные ключи в байты
        classical_pub_bytes = self.classical_public.export_key(format="raw")
        # pqc_public уже в байтах

        # Конкатенируем ключи для хэширования
        combined_pub = classical_pub_bytes + self.pqc_public

        # Вычисляем хэш (SHA256)
        pub_hash = hashlib.sha256(combined_pub).digest()

        # Формируем адрес: [версия:1 байт] + [ID алгоритма:2 байта] + [хэш:32 байта] + [контр. сумма:4 байта]
        version = b"\x01"  # Версия 1
        algo_id = b"\x02\x01"  # 0x0201 = гибридный Ed25519 + ML-DSA-65

        # Вычисляем контрольную сумму (первые 4 байта от двойного хэша)
        checksum = hashlib.sha256(
            hashlib.sha256(version + algo_id + pub_hash).digest()
        ).digest()[:4]

        # Собираем адрес (в байтах)
        address_bytes = version + algo_id + pub_hash + checksum

        # Для удобства возвращаем hex-строку с префиксом 0x
        return "0x" + address_bytes.hex()

    def save_to_file(self, directory: str = "./keys") -> None:
        """Сохраняет ключи в файлы для последующего использования."""
        if self.classical_private is None or self.pqc_private is None:
            raise ValueError("Нет ключей для сохранения. Вызовите generate() сначала.")

        os.makedirs(directory, exist_ok=True)

        # Сохраняем классические ключи в PEM формате
        with open(f"{directory}/ed25519_private.pem", "w") as f:
            f.write(self.classical_private.export_key(format="PEM"))  # type: ignore

        with open(f"{directory}/ed25519_public.pem", "w") as f:
            f.write(self.classical_public.export_key(format="PEM"))  # type: ignore

        # Сохраняем постквантовые ключи в бинарном формате
        with open(f"{directory}/mldsa65_private.bin", "wb") as f:
            f.write(self.pqc_private)

        with open(f"{directory}/mldsa65_public.bin", "wb") as f:
            f.write(self.pqc_public)  # type: ignore

        # Сохраняем адрес
        with open(f"{directory}/address.txt", "w") as f:
            f.write(self.address)  # type: ignore

        print(f"Ключи сохранены в директорию {directory}")
        print(f"Адрес: {self.address}")

    @classmethod
    def load_from_file(cls, directory: str = "./keys") -> "HybridKeyPair":
        """Загружает ключи из файлов."""
        hybrid = cls()

        # Загружаем классические ключи
        with open(f"{directory}/ed25519_private.pem", "rb") as f:
            hybrid.classical_private = ECC.import_key(f.read())

        with open(f"{directory}/ed25519_public.pem", "rb") as f:
            hybrid.classical_public = ECC.import_key(f.read())

        # Загружаем постквантовые ключи
        with open(f"{directory}/mldsa65_private.bin", "rb") as f:
            hybrid.pqc_private = f.read()

        with open(f"{directory}/mldsa65_public.bin", "rb") as f:
            hybrid.pqc_public = f.read()

        # Загружаем адрес
        with open(f"{directory}/address.txt", "r") as f:
            hybrid.address = f.read().strip()

        return hybrid

    def get_classical_private_key(self) -> EccKey:
        """Возвращает классический приватный ключ с проверкой."""
        if self.classical_private is None:
            raise ValueError("Классический приватный ключ не инициализирован")
        return self.classical_private

    def get_classical_public_key(self) -> EccKey:
        """Возвращает классический публичный ключ с проверкой."""
        if self.classical_public is None:
            raise ValueError("Классический публичный ключ не инициализирован")
        return self.classical_public

    def get_pqc_private_key(self) -> bytes:
        """Возвращает постквантовый приватный ключ с проверкой."""
        if self.pqc_private is None:
            raise ValueError("Постквантовый приватный ключ не инициализирован")
        return self.pqc_private

    def get_pqc_public_key(self) -> bytes:
        """Возвращает постквантовый публичный ключ с проверкой."""
        if self.pqc_public is None:
            raise ValueError("Постквантовый публичный ключ не инициализирован")
        return self.pqc_public
