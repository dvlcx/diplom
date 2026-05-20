import json
import os
import sys

from eth_account import Account
from web3 import Web3

# Добавляем путь к модулям
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from blockchain_client import BlockchainClient
from hybrid_key_pair import HybridKeyPair
from hybrid_signer import HybridSigner


def test_verification_with_client():
    """Тест верификации с использованием BlockchainClient"""
    print("=== Тестирование HybridVerifier ===")

    # Подключаемся к Anvil
    RPC_URL = "http://127.0.0.1:8545"
    PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

    # Создаем клиент
    client = BlockchainClient(RPC_URL, PRIVATE_KEY)
    print(f"✓ Подключено к {RPC_URL}")
    print(f"✓ Аккаунт: {client.address}")

    # Получаем адрес контракта (нужно подставить ваш адрес после деплоя)
    CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"  # Измените на ваш

    # Создаем тестовые данные
    test_signature = bytes([i % 256 for i in range(3300)])
    test_public_key = bytes([(i + 100) % 256 for i in range(2000)])
    test_message = Web3.keccak(text="Test message for ML-DSA-65")

    print(f"\nТестовые данные:")
    print(f"  - Размер подписи: {len(test_signature)} байт")
    print(f"  - Размер публичного ключа: {len(test_public_key)} байт")
    print(f"  - Сообщение: {test_message.hex()[:32]}...")

    # ABI для контракта
    abi = [
        {
            "inputs": [
                {"internalType": "bytes", "name": "pqcSignature", "type": "bytes"},
                {"internalType": "bytes", "name": "pqcPublicKey", "type": "bytes"},
                {"internalType": "bytes32", "name": "message", "type": "bytes32"},
            ],
            "name": "submitAndVerify",
            "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
            "stateMutability": "nonpayable",
            "type": "function",
        },
        {
            "inputs": [],
            "name": "verifiedTransactionsLength",
            "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
            "stateMutability": "view",
            "type": "function",
        },
        {
            "inputs": [],
            "name": "verifier",
            "outputs": [
                {
                    "internalType": "contract MLDSAVerifier",
                    "name": "",
                    "type": "address",
                }
            ],
            "stateMutability": "view",
            "type": "function",
        },
    ]

    contract = client.w3.eth.contract(address=CONTRACT_ADDRESS, abi=abi)

    # Проверяем, что контракт существует
    code = client.w3.eth.get_code(CONTRACT_ADDRESS)
    if code == b"":
        print(f"\n❌ Контракт не найден по адресу {CONTRACT_ADDRESS}")
        print("Убедитесь, что контракт развернут, и укажите правильный адрес")
        return

    print(f"✓ Контракт найден по адресу {CONTRACT_ADDRESS}")

    # Получаем адрес верификатора
    try:
        verifier_addr = contract.functions.verifier().call()
        print(f"✓ Verifier адрес: {verifier_addr}")
    except Exception as e:
        print(f"⚠️ Не удалось получить verifier: {e}")

    # Получаем текущий nonce
    nonce = client.w3.eth.get_transaction_count(client.address)
    print(f"\nNonce: {nonce}")

    # Оцениваем газ
    try:
        gas_estimate = contract.functions.submitAndVerify(
            test_signature, test_public_key, test_message
        ).estimate_gas({"from": client.address})
        print(f"Оценка газа: {gas_estimate}")
        gas_limit = int(gas_estimate * 1.5)
    except Exception as e:
        print(f"⚠️ Ошибка оценки газа: {e}")
        print("Используем лимит 5,000,000")
        gas_limit = 20000000

    print(f"Лимит газа: {gas_limit}")

    # Создаем и отправляем транзакцию
    print("\nОтправка транзакции...")
    try:
        tx = contract.functions.submitAndVerify(
            test_signature, test_public_key, test_message
        ).build_transaction(
            {
                "from": client.address,
                "nonce": nonce,
                "gas": gas_limit,
                "gasPrice": client.w3.eth.gas_price,
                "chainId": client.w3.eth.chain_id,
            }
        )

        signed_tx = client.account.sign_transaction(tx)
        tx_hash = client.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        print(f"Транзакция отправлена: {tx_hash.hex()}")

        # Ждем подтверждения с таймаутом
        receipt = client.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

        print(f"\nРезультат:")
        print(f"  - Статус: {'✅ успех' if receipt['status'] == 1 else '❌ неудача'}")
        print(f"  - Блок: {receipt['blockNumber']}")
        print(f"  - Газ использовано: {receipt['gasUsed']}")

        if receipt["status"] == 0:
            print("\n❌ Транзакция завершилась с ошибкой!")
            print("Попытка получить причину ошибки...")

            # Пытаемся вызвать функцию с теми же параметрами, чтобы получить revert reason
            try:
                contract.functions.submitAndVerify(
                    test_signature, test_public_key, test_message
                ).call({"from": client.address})
            except Exception as call_error:
                print(f"Причина ошибки: {call_error}")

            # Выводим логи транзакции
            print(f"\nЛоги транзакции:")
            for log in receipt["logs"]:
                print(f"  - {log}")
        else:
            # Проверяем количество верифицированных транзакций
            count = contract.functions.verifiedTransactionsLength().call()
            print(f"\nКоличество верифицированных транзакций: {count}")

    except Exception as e:
        print(f"❌ Ошибка при отправке транзакции: {e}")

    print("\n✅ Тестирование завершено!")


if __name__ == "__main__":
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ HYBRID VERIFIER")
    print("=" * 60)

    test_verification_with_client()
