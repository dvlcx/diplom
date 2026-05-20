import json
import time

import oqs

from blockchain_client import BlockchainClient
from hybrid_key_pair import HybridKeyPair
from mldsa_parser import MLDSAKeyParser  # импортируем парсер для замера


def test_verification_with_liboqs():
    """Тест верификации с реальными ключами liboqs и замером времени"""
    print("=== Тестирование верификации ML-DSA-65 ===")
    total_start = time.time()

    # Подключаемся к Anvil
    RPC_URL = "http://127.0.0.1:8545"
    PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

    client = BlockchainClient(RPC_URL, PRIVATE_KEY)
    print(f"✓ Аккаунт: {client.address}")

    CONTRACT_ADDRESS = (
        "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"  # замените на актуальный
    )

    with open("out/HybridVerifier.sol/HybridVerifier.json") as f:
        contract_json = json.load(f)
        abi = contract_json["abi"]

    # ---- Генерация ключей ----
    t0 = time.time()
    hybrid_keypair = HybridKeyPair().generate()
    t_gen = time.time() - t0
    print(f"\n[1] Генерация ключей ML-DSA-65: {t_gen:.3f} сек")
    print(f"    Публичный ключ: {len(hybrid_keypair.pqc_public)} байт")

    # Сообщение
    message = b"Test message for ML-DSA-65 verification"
    message_hash = client.w3.keccak(message)
    print(f"    Хэш сообщения: {message_hash.hex()[:32]}...")

    # ---- Подписание ----
    t0 = time.time()
    dilithium = oqs.Signature("Dilithium3", hybrid_keypair.pqc_private)
    ml_dsa_signature = dilithium.sign(message_hash)
    dilithium.free()
    t_sign = time.time() - t0
    print(f"\n[2] Подписание сообщения: {t_sign:.3f} сек")
    print(f"    Подпись: {len(ml_dsa_signature)} байт")

    # ---- Парсинг публичного ключа и подписи ----
    t0 = time.time()
    A, t, rho = MLDSAKeyParser.parse_public_key(hybrid_keypair.pqc_public)
    pk_struct = {"A": A, "t": t, "rho": rho}
    z, h, c = MLDSAKeyParser.parse_signature(ml_dsa_signature)
    sig_struct = {"z": z, "h": h, "c": c}
    t_parse = time.time() - t0
    print(f"\n[3] Парсинг ключа и подписи: {t_parse:.3f} сек")

    # ---- Отправка транзакции в контракт ----
    print("\n[4] Отправка транзакции в контракт...")
    t0 = time.time()
    success, receipt = client.verify_ml_dsa_signature_on_chain(
        contract_address=CONTRACT_ADDRESS,
        contract_abi=abi,
        ml_dsa_public_key=hybrid_keypair.pqc_public,
        ml_dsa_signature=ml_dsa_signature,
        message_hash=message_hash,
        gas_limit=10_000_000,
    )
    t_tx = time.time() - t0

    print(f"\n[5] Время отправки + подтверждения: {t_tx:.3f} сек")
    if receipt:
        gas_used = receipt.get("gasUsed", 0)
        print(f"    Использовано газа: {gas_used}")
        block_number = receipt.get("blockNumber", 0)
        print(f"    Блок: {block_number}")

    if success:
        print("\n✅ Верификация успешна!")
        # Проверяем количество верифицированных транзакций
        contract = client.w3.eth.contract(address=CONTRACT_ADDRESS, abi=abi)
        count = contract.functions.verifiedTransactionsLength().call()
        print(f"Количество верифицированных транзакций: {count}")
    else:
        print("\n❌ Верификация не удалась")

    total_time = time.time() - total_start
    print(f"\n--- Общее время выполнения: {total_time:.3f} сек ---")


if __name__ == "__main__":
    test_verification_with_liboqs()
