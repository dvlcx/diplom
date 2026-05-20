import json
import os
import sys
import time

from eth_account import Account
from web3 import Web3

# Подключаемся к Anvil
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
assert w3.is_connected(), "Not connected to Anvil"

# Адрес контракта (из деплоя)
CONTRACT_ADDRESS = "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318"

# ABI контракта
ABI = [
    {
        "inputs": [],
        "name": "getSignaturesCount",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "bytes", "name": "pqcSignature", "type": "bytes"},
            {"internalType": "bytes", "name": "pqcPublicKey", "type": "bytes"},
            {"internalType": "bytes32", "name": "txHash", "type": "bytes32"},
        ],
        "name": "submitSignature",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "signatureId", "type": "uint256"}
        ],
        "name": "getSignature",
        "outputs": [
            {"internalType": "address", "name": "sender", "type": "address"},
            {"internalType": "bytes32", "name": "txHash", "type": "bytes32"},
            {"internalType": "bytes", "name": "pqcSignature", "type": "bytes"},
            {"internalType": "bytes", "name": "pqcPublicKey", "type": "bytes"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"internalType": "bool", "name": "verified", "type": "bool"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "signatureId", "type": "uint256"},
            {"internalType": "bool", "name": "verified", "type": "bool"},
            {"internalType": "string", "name": "reason", "type": "string"},
        ],
        "name": "setVerificationStatus",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "message", "type": "bytes32"},
            {"internalType": "bytes", "name": "signature", "type": "bytes"},
            {"internalType": "bytes", "name": "publicKey", "type": "bytes"},
        ],
        "name": "verifyPQCSignature",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "pure",
        "type": "function",
    },
]

# Создаем контракт
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)

# Аккаунт для отправки транзакций (первый аккаунт Anvil)
PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
account = Account.from_key(PRIVATE_KEY)


def test_contract():
    print("=== Тестирование смарт-контракта ===")

    # 1. Проверяем начальное состояние
    count = contract.functions.getSignaturesCount().call()
    print(f"1. Начальное количество подписей: {count}")

    # 2. Создаем тестовые данные (уменьшаем размер для теста)
    # ML-DSA-65 требует ~3300 байт, но для теста используем 3300
    test_signature = bytes([i % 256 for i in range(3300)])
    test_public_key = bytes([(i + 100) % 256 for i in range(2000)])
    test_tx_hash = w3.keccak(text="test transaction")

    print(f"\n2. Размер подписи: {len(test_signature)} байт")
    print(f"   Размер публичного ключа: {len(test_public_key)} байт")

    # 3. Отправляем подпись с увеличенным лимитом газа
    print("\n3. Отправка подписи...")

    # Сначала оцениваем газ
    try:
        gas_estimate = contract.functions.submitSignature(
            test_signature, test_public_key, test_tx_hash
        ).estimate_gas({"from": account.address})
        print(f"   Оценка газа: {gas_estimate}")
    except Exception as e:
        print(f"   Ошибка оценки газа: {e}")
        gas_estimate = 2000000  # Увеличиваем лимит

    # Отправляем с запасом
    tx = contract.functions.submitSignature(
        test_signature, test_public_key, test_tx_hash
    ).build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gas": int(gas_estimate * 1.5),  # Добавляем 50% запаса
            "gasPrice": w3.eth.gas_price,
        }
    )

    print(f"   Лимит газа: {tx['gas']}")

    signed_tx = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

    # Ждем подтверждения с таймаутом
    print("   Ожидание подтверждения...")
    try:
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        print(f"   Транзакция подтверждена: {tx_hash.hex()}")
        print(f"   Статус: {'успех' if receipt['status'] == 1 else 'неудача'}")
        print(f"   Использовано газа: {receipt['gasUsed']}")

        if receipt["status"] != 1:
            print("   ❌ Транзакция не удалась!")
            # Пытаемся получить причину
            try:
                w3.eth.call(tx, block_identifier=receipt["blockNumber"])
            except Exception as call_error:
                print(f"   Причина: {call_error}")
            return
    except Exception as e:
        print(f"   ❌ Ошибка при ожидании подтверждения: {e}")
        return

    # 4. Проверяем количество подписей
    count = contract.functions.getSignaturesCount().call()
    print(f"\n4. Количество подписей после отправки: {count}")

    if count == 0:
        print("   ❌ Подпись не сохранена! Проверьте контракт и лимит газа.")
        return

    # 5. Получаем информацию о подписи
    print("\n5. Получение информации о подписи...")
    try:
        signature_data = contract.functions.getSignature(0).call()
        print(f"   Отправитель: {signature_data[0]}")
        print(f"   Хэш транзакции: {signature_data[1].hex()}")
        print(f"   Размер подписи: {len(signature_data[2])} байт")
        print(f"   Размер публичного ключа: {len(signature_data[3])} байт")
        print(f"   Время: {signature_data[4]}")
        print(f"   Верифицирована: {signature_data[5]}")
    except Exception as e:
        print(f"   ❌ Ошибка получения подписи: {e}")
        return

    # 6. Устанавливаем статус верификации (только владелец)
    print("\n6. Установка статуса верификации...")
    tx = contract.functions.setVerificationStatus(
        0, True, "Verified by oracle"
    ).build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gas": 200000,
            "gasPrice": w3.eth.gas_price,
        }
    )

    signed_tx = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"   Статус: {'успех' if receipt['status'] == 1 else 'неудача'}")
    print(f"   Использовано газа: {receipt['gasUsed']}")

    if receipt["status"] == 1:
        # 7. Проверяем обновленный статус
        signature_data = contract.functions.getSignature(0).call()
        print(f"   Обновленный статус верификации: {signature_data[5]}")

    # 8. Тестируем заглушку верификации
    print("\n7. Тестирование заглушки verifyPQCSignature...")
    is_valid = contract.functions.verifyPQCSignature(
        test_tx_hash, test_signature, test_public_key
    ).call()
    print(f"   Результат верификации (заглушка): {is_valid}")

    print("\n✅ Тестирование завершено!")


if __name__ == "__main__":
    test_contract()
