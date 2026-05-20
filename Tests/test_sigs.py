#!/usr/bin/env python3
"""
Бенчмарк для измерения времени генерации ключей и подписания.
Сравниваются: Ed25519 (классический), ECDSA on secp256k1 и ML-DSA-65 (Dilithium3).
Результаты сохраняются в CSV-файл и выводятся в консоль.
"""

import csv
import hashlib
import statistics
import time

import nacl.signing
import oqs
from coincurve import PrivateKey
from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa


def benchmark_ed25519(iterations=1000):
    """Бенчмарк для Ed25519 (PyCryptodome)."""
    gen_times, sign_times = [], []
    message = b"Test message for Ed25519"

    for _ in range(iterations):
        # 1. Честный замер генерации ключей (на Си)
        start = time.perf_counter()
        signing_key = nacl.signing.SigningKey.generate()
        # Вызов public_key здесь, если нужен экспорт
        _ = signing_key.verify_key
        gen_times.append(time.perf_counter() - start)

        # 2. Честный замер подписания (без лишней инициализации объектов на Python)
        start = time.perf_counter()
        _ = signing_key.sign(message)
        sign_times.append(time.perf_counter() - start)

    return {
        "name": "Ed25519 (PyNaCl/libsodium)",
        "gen_avg": statistics.mean(gen_times) * 1000,
        "gen_std": statistics.stdev(gen_times) * 1000,
        "sign_avg": statistics.mean(sign_times) * 1000,
        "sign_std": statistics.stdev(sign_times) * 1000,
    }


def benchmark_secp256k1(iterations=1000):
    """Бенчмарк для ECDSA on secp256k1 (coincurve)."""
    gen_times, sign_times = [], []
    message = b"Test message for secp256k1"
    hashed_message = hashlib.sha256(message).digest()

    for _ in range(iterations):
        # Генерация ключей
        start = time.perf_counter()
        pk = PrivateKey()  # Генерация нового приватного ключа
        public_key = pk.public_key.format(compressed=False)
        gen_times.append(time.perf_counter() - start)

        # Подписание
        start = time.perf_counter()
        signature = pk.sign(hashed_message, hasher=None)
        sign_times.append(time.perf_counter() - start)

    return {
        "name": "ECDSA (secp256k1)",
        "gen_avg": statistics.mean(gen_times) * 1000,
        "gen_std": statistics.stdev(gen_times) * 1000,
        "sign_avg": statistics.mean(sign_times) * 1000,
        "sign_std": statistics.stdev(sign_times) * 1000,
    }


def benchmark_mldsa65(iterations=1000):
    """Бенчмарк для ML-DSA-65 (Dilithium3) через liboqs."""
    gen_times, sign_times = [], []
    message = b"Test message for ML-DSA-65"

    for _ in range(iterations):
        dilithium = oqs.Signature("Dilithium3")
        # Генерация ключей
        start = time.perf_counter()
        public_key = dilithium.generate_keypair()
        private_key = dilithium.export_secret_key()
        gen_times.append(time.perf_counter() - start)

        # Подписание
        start = time.perf_counter()
        signature = dilithium.sign(message)
        sign_times.append(time.perf_counter() - start)

        dilithium.free()

    return {
        "name": "ML-DSA-65 (Dilithium3)",
        "gen_avg": statistics.mean(gen_times) * 1000,
        "gen_std": statistics.stdev(gen_times) * 1000,
        "sign_avg": statistics.mean(sign_times) * 1000,
        "sign_std": statistics.stdev(sign_times) * 1000,
    }


def print_results(results):
    """Выводит результаты в читаемом виде."""
    print("\n" + "=" * 80)
    print("РЕЗУЛЬТАТЫ БЕНЧМАРКА (10 итераций, время в миллисекундах)")
    print("=" * 80)
    for r in results:
        print(f"\n{r['name']}:")
        print(f"  Генерация ключей: {r['gen_avg']:.3f} ± {r['gen_std']:.3f} мс")
        print(f"  Подписание:        {r['sign_avg']:.3f} ± {r['sign_std']:.3f} мс")


if __name__ == "__main__":
    print("🚀 Запуск бенчмарка криптографических алгоритмов...")
    results = []
    results.append(benchmark_ed25519())
    results.append(benchmark_secp256k1())
    results.append(benchmark_mldsa65())
    print_results(results)
