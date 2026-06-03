import json
from typing import Any, Tuple

from eth_abi.abi import encode
from eth_account import Account
from web3 import Web3
from web3.providers import HTTPProvider
from web3.types import TxParams, Wei

from hybrid_signer import HybridSigner


class BlockchainClient:
    def __init__(self, rpc_url: str, private_key: str = None):
        self.w3 = Web3(HTTPProvider(rpc_url))
        if not self.w3.is_connected():
            raise ConnectionError(f"Не удалось подключиться к {rpc_url}")

        if private_key:
            self.account = Account.from_key(private_key)
            self.address = self.account.address
        else:
            self.account = None
            self.address = None

    def _ensure_address(self):
        if self.address is None:
            raise ValueError("Адрес не инициализирован: укажите private_key при создании клиента")

    def send_hybrid_transaction(
        self,
        hybrid_signer: HybridSigner,
        to_address: str,
        value: int = 0,
        data: bytes = b"",
    ) -> dict[str, Any]:
        self._ensure_address()
        nonce = self.w3.eth.get_transaction_count(self.address)

        tx_for_signing = {
            "nonce": nonce,
            "to": to_address,
            "value": value,
            "gas": 3_000_000,
            "gasPrice": self.w3.eth.gas_price,
            "data": data,
            "chainId": self.w3.eth.chain_id,
        }
        signed_tx_dict = hybrid_signer.sign_transaction(tx_for_signing)

        # Более эффективная упаковка: бинарный формат вместо JSON
        sig = signed_tx_dict["signature"]
        classical = bytes.fromhex(sig["classical"][2:])
        pqc = bytes.fromhex(sig["pqc"][2:])
        pqc_pub = bytes.fromhex(sig["pqc_public_key"][2:])
        packed = b"HYBRID:" + classical + pqc + pqc_pub

        final_tx_params: TxParams = {
            "nonce": nonce,
            "to": to_address,
            "value": Wei(value),
            "gas": 3_000_000,
            "gasPrice": self.w3.eth.gas_price,
            "data": packed,
            "chainId": self.w3.eth.chain_id,
            "from": self.address,
        }

        try:
            gas_estimate = self.w3.eth.estimate_gas(final_tx_params)
            final_tx_params["gas"] = int(gas_estimate * 1.2)
        except Exception as e:
            print(f"Ошибка оценки газа: {e}")

        signed_txn = self.w3.eth.account.sign_transaction(
            final_tx_params, self.account.key
        )
        tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        print(f"Транзакция отправлена. Хэш: {tx_hash.hex()}")

        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"Транзакция подтверждена в блоке {receipt['blockNumber']}")
        print(f"Статус: {'успех' if receipt['status'] == 1 else 'неудача'}")
        return dict(receipt)

    # Добавить в класс BlockchainClient

    def simulate_hybrid_verify_call(
        self,
        contract_address: str,
        contract_abi: list,
        classic_pk: bytes,
        classic_sig: bytes,
        pqc_pk: bytes,
        pqc_sig: bytes,
        message: bytes,
    ) -> Tuple[bool, str]:
        self._ensure_address()
        contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)
        try:
            result = contract.functions.submitHybrid(
                classic_pk, classic_sig, pqc_pk, pqc_sig, message
            ).call({"from": self.address})
            return True, str(result)
        except Exception as e:
            return False, str(e)

    def hybrid_verify_on_chain(
    self,
    contract_address: str,
    contract_abi: list,
    classic_pk: bytes,
    classic_sig: bytes,
    pqc_pk: bytes,
    pqc_sig: bytes,
    message: bytes,
    gas_limit: int = 100_000_000,
    ) -> Tuple[bool, dict]:
        self._ensure_address()
        contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)
        nonce = self.w3.eth.get_transaction_count(self.address)

        tx = contract.functions.submitHybrid(
            classic_pk, classic_sig, pqc_pk, pqc_sig, message
        ).build_transaction({
            "from": self.address,
            "nonce": nonce,
            "gas": gas_limit,
            "gasPrice": self.w3.eth.gas_price,
        })

        try:
            estimated = self.w3.eth.estimate_gas(tx)
            tx["gas"] = int(estimated * 1.2)
        except Exception:
            pass

        signed = self.account.sign_transaction(tx)
        # Исправлено: raw_transaction вместо rawTransaction
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        print(f"    TX хэш: {tx_hash.hex()}")

        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        success = receipt["status"] == 1
        if not success:
            try:
                self.w3.eth.call(tx, block_identifier=receipt["blockNumber"])
            except Exception as e:
                print(f"    Revert: {e}")
        return success, dict(receipt)  
    
    def verify_ml_dsa_signature_on_chain(
        self,
        contract_address: str,
        contract_abi: list,
        ml_dsa_public_key: bytes,
        ml_dsa_signature: bytes,
        message_hash: bytes,
        gas_limit: int = 100_000_000,
    ) -> Tuple[bool, dict]:
        self._ensure_address()
        contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)
        nonce = self.w3.eth.get_transaction_count(self.address)

        tx = contract.functions.submitAndVerify(
            ml_dsa_public_key,
            ml_dsa_signature,
            message_hash
        ).build_transaction({
            "from": self.address,
            "nonce": nonce,
            "gas": gas_limit,
            "gasPrice": self.w3.eth.gas_price,
        })

        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        print(f"Tx hash: {tx_hash.hex()}")

        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        success = receipt["status"] == 1
        if not success:
            try:
                self.w3.eth.call(tx, block_identifier=receipt["blockNumber"])
            except Exception as e:
                print(f"Revert reason: {e}")
        return success, dict(receipt)

    def simulate_verify_call(
        self,
        contract_address: str,
        contract_abi: list,
        ml_dsa_public_key: bytes,
        ml_dsa_signature: bytes,
        message_hash: bytes,
    ) -> Tuple[bool, str]:
        self._ensure_address()
        contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)
        try:
            result = contract.functions.submitAndVerify(
                ml_dsa_public_key, ml_dsa_signature, message_hash
            ).call({"from": self.address})
            return True, str(result)
        except Exception as e:
            return False, str(e)