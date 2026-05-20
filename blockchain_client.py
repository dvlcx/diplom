import json
from typing import Any, Tuple

import eth_abi
from eth_abi.abi import encode
from eth_account import Account
from web3 import Web3
from web3.providers import HTTPProvider
from web3.types import TxParams, Wei

from hybrid_signer import HybridSigner
from mldsa_parser import MLDSAKeyParser


class BlockchainClient:
    """Клиент для взаимодействия с блокчейном Ethereum."""

    def __init__(self, rpc_url, private_key=None):
        self.w3 = Web3(HTTPProvider(rpc_url))
        if not self.w3.is_connected():
            raise ConnectionError(f"Не удалось подключиться к {rpc_url}")

        if private_key:
            self.account = Account.from_key(private_key)
            self.address = self.account.address

    def send_hybrid_transaction(
        self,
        hybrid_signer: HybridSigner,
        to_address: str,
        value: int = 0,
        data: bytes = b"",
    ) -> dict[str, Any]:
        # 1. Получаем nonce
        nonce = self.w3.eth.get_transaction_count(self.address)

        # 2. Подписываем гибридно транзакцию (без финальных данных)
        tx_for_signing = {
            "nonce": nonce,
            "to": to_address,
            "value": value,
            "gas": 3_000_000,  # временное значение
            "gasPrice": self.w3.eth.gas_price,
            "data": data,  # исходные данные (может быть b"")
            "chainId": self.w3.eth.chain_id,
        }
        signed_tx_dict = hybrid_signer.sign_transaction(tx_for_signing)

        # 3. Упаковываем подпись в data
        signature_json = json.dumps(signed_tx_dict["signature"])
        tx_data = b"HYBRID:" + signature_json.encode()

        # 4. Формируем финальные параметры транзакции
        final_tx_params: TxParams = {
            "nonce": nonce,
            "to": to_address,
            "value": Wei(value),
            "gas": 3_000_000,
            "gasPrice": self.w3.eth.gas_price,
            "data": tx_data,
            "chainId": self.w3.eth.chain_id,
            "from": self.address,
        }

        # 5. Оцениваем газ с учётом реальных данных
        try:
            gas_estimate = self.w3.eth.estimate_gas(final_tx_params)
            final_tx_params["gas"] = int(gas_estimate * 1.2)
        except Exception as e:
            print(f"Ошибка оценки газа: {e}")

        # 6. Классическая подпись и отправка
        signed_txn = self.w3.eth.account.sign_transaction(
            final_tx_params, self.account.key
        )
        tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        print(f"Транзакция отправлена. Хэш: {tx_hash.hex()}")

        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"Транзакция подтверждена в блоке {receipt['blockNumber']}")
        print(f"Статус: {'успех' if receipt['status'] == 1 else 'неудача'}")

        return dict(receipt)

    def verify_ml_dsa_signature_on_chain(
        self,
        contract_address: str,
        contract_abi: list,
        ml_dsa_public_key: bytes,
        ml_dsa_signature: bytes,
        message_hash: bytes,
        gas_limit: int = 100_000_000,
    ) -> Tuple[bool, dict]:
        # 1. Парсим ключ и подпись в структуры (как у вас уже было)
        A, t, rho = MLDSAKeyParser.parse_public_key(ml_dsa_public_key)
        pk_struct = {"A": A, "t": t, "rho": rho}

        z, h, c = MLDSAKeyParser.parse_signature(ml_dsa_signature)
        sig_struct = {
            "z": z,
            "h": h,
            "c": "0x" + c.hex() if isinstance(c, bytes) else c,
        }

        # 2. Кодируем структуры в ABI-байты
        # Типы: publicKey (tuple), signature (tuple)
        pk_tuple = (A, t, rho)
        # Тип: кортеж из трёх компонентов: uint256[][][], uint256[][], uint256[][]
        pk_encoded = encode(["(uint256[][][],uint256[][],uint256[][])"], [pk_tuple])

        # 2. Кодируем подпись как один кортеж
        sig_tuple = (z, h, c)  # c — bytes32
        sig_encoded = encode(["(uint256[][],uint256[][],bytes32)"], [sig_tuple])

        # 3. Вызываем контракт с байтовыми параметрами
        contract: Contract = self.w3.eth.contract(
            address=contract_address, abi=contract_abi
        )

        # Вариант A: через build_transaction
        nonce = self.w3.eth.get_transaction_count(self.address)
        tx = contract.functions.submitAndVerify(
            pk_encoded, sig_encoded, message_hash
        ).build_transaction(
            {
                "from": self.address,
                "nonce": nonce,
                "gas": gas_limit,
                "gasPrice": self.w3.eth.gas_price,
            }
        )

        # Вариант B: если хотите использовать encodeABI напрямую
        # data = contract.encodeABI(fn_name="submitAndVerify", args=[pk_encoded, sig_encoded, message_hash])

        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        print(f"Транзакция отправлена: {tx_hash.hex()}")

        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        success = receipt["status"] == 1
        print(f"Статус: {'✅ успех' if success else '❌ неудача'}")
        print(f"Газ использовано: {receipt['gasUsed']}")
        return success, dict(receipt)

    def simulate_verify_call(
        self,
        contract_address: str,
        contract_abi: list,
        ml_dsa_public_key: bytes,
        ml_dsa_signature: bytes,
        message_hash: bytes,
    ) -> Tuple[bool, str]:
        """Симулирует вызов submitAndVerify, возвращает success и сообщение об ошибке."""
        contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)
        try:
            result = contract.functions.submitAndVerify(
                ml_dsa_public_key, ml_dsa_signature, message_hash
            ).call({"from": self.address})
            return True, str(result)
        except Exception as e:
            return False, str(e)
