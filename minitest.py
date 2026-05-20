import json

from eth_account import Account
from web3 import Web3
from web3.exceptions import ContractLogicError

RPC_URL = "http://127.0.0.1:8545"
PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
CONTRACT_ADDRESS = (
    "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"  # замените на актуальный
)

w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = Account.from_key(PRIVATE_KEY)

with open("out/HybridVerifier.sol/HybridVerifier.json") as f:
    contract_json = json.load(f)
    abi = contract_json["abi"]

# Параметры – должны совпадать с контрактом
N = 256
K = 6

L = 5


def empty_poly():
    return [0] * N


# Публичный ключ (нулевой)
pk = {
    "A": [[empty_poly() for _ in range(L)] for _ in range(K)],
    "t": [empty_poly() for _ in range(K)],
    "rho": [empty_poly()],
}


def compute_challenge_for_zero_w(msg_hash):
    input_data = b"\x00"
    for _ in range(K):
        for _ in range(N):
            input_data += (0).to_bytes(32, "big")
    input_data += msg_hash
    return w3.keccak(input_data)


message = b"Test message"
message_hash = w3.keccak(message)

sig = {
    "z": [empty_poly() for _ in range(L)],
    "h": [empty_poly() for _ in range(K)],
    "c": compute_challenge_for_zero_w(message_hash),
}

contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=abi)

# Оценка газа
nonce = w3.eth.get_transaction_count(account.address)
gas_price = w3.eth.gas_price


tx = contract.functions.submitAndVerify(sig, pk, message_hash).build_transaction(
    {
        "from": account.address,
        "nonce": nonce,
    }
)
signed = account.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
print(f"Tx hash: {tx_hash.hex()}")
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print(f"Статус: {receipt['status']}")
print("\n" + "=" * 60)
print("RECEIPT DETAILS:")
print("=" * 60)
print(f"Transaction hash: {receipt['transactionHash'].hex()}")
print(f"Block number: {receipt['blockNumber']}")
print(f"Block hash: {receipt['blockHash'].hex()}")
print(f"Status: {'SUCCESS' if receipt['status'] == 1 else 'FAILED'}")
print(f"Gas used: {receipt['gasUsed']}")
print(f"Cumulative gas used: {receipt['cumulativeGasUsed']}")
print(f"From: {receipt['from']}")
print(f"To: {receipt['to']}")
print(f"Logs count: {len(receipt['logs'])}")
