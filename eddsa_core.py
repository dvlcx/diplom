import subprocess
from typing import Tuple

class EdDSACore:
    def __init__(self, binary_path: str = "./eddsa_core/target/release/eddsa_core"):
        self.binary_path = binary_path

    def generate(self) -> Tuple[bytes, bytes]:
        result = subprocess.run(
            [self.binary_path, "gen"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5
        )
        lines = result.stdout.strip().splitlines()
        if len(lines) < 2:
            raise RuntimeError(f"Неожиданный вывод: {result.stdout}")
        return bytes.fromhex(lines[0].strip()), bytes.fromhex(lines[1].strip())

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        result = subprocess.run(
            [self.binary_path, "sign", private_key.hex(), message.hex()],
            capture_output=True,
            text=True,
            check=True,
            timeout=5
        )
        return bytes.fromhex(result.stdout.strip())

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        result = subprocess.run(
            [self.binary_path, "verify", public_key.hex(), message.hex(), signature.hex()],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout.strip() == "OK"

    def run_benchmark(self, iterations: int, message: bytes) -> Tuple[float, float]:
        result = subprocess.run(
            [self.binary_path, "bench", str(iterations), message.hex()],
            capture_output=True,
            text=True,
            check=True,
            timeout=30
        )
        lines = result.stdout.strip().splitlines()
        if len(lines) < 2:
            raise RuntimeError(f"Неожиданный вывод бенчмарка: {result.stdout}")
        return float(lines[0].strip()), float(lines[1].strip())
