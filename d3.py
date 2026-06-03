import json
import time
from web3 import Web3
from web3.providers import HTTPProvider
from eth_account import Account
from eth_keys import keys

# Включаем HD-фичи (для совместимости)
Account.enable_unaudited_hdwallet_features()

def test_ecdsa_verifier():
    RPC_URL = "http://127.0.0.1:8545"
    w3 = Web3(HTTPProvider(RPC_URL))
    if not w3.is_connected():
        raise ConnectionError(f"Не удалось подключиться к {RPC_URL}")
    print(f"✓ Подключено к узлу, chain ID: {w3.eth.chain_id}")

    ECDSA_VERIFIER_ADDRESS = "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853"

    with open("out/ECDSAVerifier.sol/ECDSAVerifier.json", "r") as f:
        contract_data = json.load(f)
        abi = contract_data["abi"]

    contract = w3.eth.contract(address=ECDSA_VERIFIER_ADDRESS, abi=abi)

    PRIVATE_KEY_HEX = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    message = b"Hello"

    message_hash = w3.keccak(message)

    signed = Account.unsafe_sign_hash(message_hash, private_key=PRIVATE_KEY_HEX)
    signature = signed.signature

    private_key_bytes = bytes.fromhex(PRIVATE_KEY_HEX[2:])
    private_key_obj = keys.PrivateKey(private_key_bytes)
    public_key_bytes = private_key_obj.public_key.to_bytes()

    print(f"\n[1] Статические данные сгенерированы:")
    print(f"    Публичный ключ: {len(public_key_bytes)} байт (ожидается 64)")
    print(f"    Подпись: {len(signature)} байт (ожидается 65)")
    print(f"    Сообщение: {message.decode()}")
    print(f"    Хэш сообщения: 0x{message_hash.hex()}")

    print("\n[2] Прогон 1000 вызовов verifyRaw...")
    iterations = 1000
    times = []


    for i in range(iterations):
        t_start = time.time()
        result = contract.functions.verifyRaw(public_key_bytes, signature, message).transact()
        t_end = time.time()
        times.append(t_end - t_start)
        if i == 0:
            if not result:
                print("   Предупреждение: первый вызов вернул False, вероятно, все вызовы будут ложными.")
        if (i + 1) % 100 == 0:
            print(f"   Прогресс: {i+1}/{iterations}")

    avg_time = sum(times) / iterations


    
    print(f"\n[3] Результаты {iterations} вызовов:")
    print(f"    Среднее время: {avg_time:.3f} с")
    print("\n✅ Все вызовы выполнены без ошибок.")

if __name__ == "__main__":
    test_ecdsa_verifier()