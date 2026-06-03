import json
import time

from blockchain_client import BlockchainClient
from hybrid_key_pair import HybridKeyPair
from ecdsa_core import ECDSACore
from dilithium_core import DilithiumCore

def test_hybrid_verification():
    print("=== Тестирование гибридной верификации (ECDSA + ML-DSA) ===")
    total_start = time.time()

    RPC_URL = "http://127.0.0.1:8545"
    PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    client = BlockchainClient(RPC_URL, PRIVATE_KEY)
    print(f"✓ Аккаунт: {client.address}")

    CONTRACT_ADDRESS = "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318"  # адрес HybridVerifier

    with open("contracts/out/HybridVerifier.sol/HybridVerifier.json") as f:
        contract_json = json.load(f)
        abi = contract_json["abi"]

    # 1. Генерация ключей
    t0 = time.time()
    hybrid_keypair = HybridKeyPair().generate()
    t_gen = time.time() - t0
    print(f"\n[1] Генерация ключей: {t_gen:.3f} сек")
    print(f"    ECDSA публичный ключ: {len(hybrid_keypair.classical_public)} байт")
    print(f"    ML-DSA публичный ключ: {len(hybrid_keypair.pqc_public)} байт")

    message = b"Hybrid test message for ECDSA + ML-DSA"

    # 2. Подпись ECDSA
    ecdsa_core = ECDSACore()
    t0 = time.time()
    ecdsa_sig = ecdsa_core.sign(hybrid_keypair.classical_private, message)
    t_ecdsa = time.time() - t0
    print(f"\n[2] Подпись ECDSA: {t_ecdsa:.3f} сек, размер {len(ecdsa_sig)} байт")

    # 3. Подпись ML-DSA
    dilithium_core = DilithiumCore()
    t0 = time.time()
    pqc_sig = dilithium_core.sign(hybrid_keypair.pqc_seed, message)
    t_pqc = time.time() - t0
    print(f"    Подпись ML-DSA: {t_pqc:.3f} сек, размер {len(pqc_sig)} байт")

    # 4. Симуляция
    print("\n[3] Симуляция вызова контракта...")
    success, msg = client.simulate_hybrid_verify_call(
        contract_address=CONTRACT_ADDRESS,
        contract_abi=abi,
        classic_pk=hybrid_keypair.classical_public,
        classic_sig=ecdsa_sig,
        pqc_pk=hybrid_keypair.pqc_public,
        pqc_sig=pqc_sig,
        message=message,
    )
    print(f"Симуляция: {success}, {msg}")

    # 5. Реальная транзакция
    t0 = time.time()
    success, receipt = client.hybrid_verify_on_chain(
        contract_address=CONTRACT_ADDRESS,
        contract_abi=abi,
        classic_pk=hybrid_keypair.classical_public,
        classic_sig=ecdsa_sig,
        pqc_pk=hybrid_keypair.pqc_public,
        pqc_sig=pqc_sig,
        message=message,
    )
    t_tx = time.time() - t0

    print(f"\n[4] Время отправки + подтверждения: {t_tx:.3f} сек")
    if receipt:
        gas_used = receipt.get("gasUsed", 0)
        print(f"    Использовано газа: {gas_used}")
        block_number = receipt.get("blockNumber", 0)
        print(f"    Блок: {block_number}")

    if success:
        print("\n✅ Гибридная верификация успешна!")
        contract = client.w3.eth.contract(address=CONTRACT_ADDRESS, abi=abi)
        count = contract.functions.verifiedTransactionsLength().call()
        print(f"Количество верифицированных транзакций: {count}")
    else:
        print("\n❌ Гибридная верификация не удалась")

    total_time = time.time() - total_start
    print(f"\n--- Общее время выполнения: {total_time:.3f} сек ---")

if __name__ == "__main__":
    test_hybrid_verification()