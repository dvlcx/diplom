import subprocess
from typing import Dict, Any, Optional
from web3 import Web3
import rlp
from dilithium_core import DilithiumCore
from ecdsa_core import ECDSACore          # Заменили EdDSACore


class HybridSigner:
    def __init__(self, hybrid_keypair,
                 ecdsa_core: Optional[ECDSACore] = None,
                 dilithium_core: Optional[DilithiumCore] = None):
        self.keypair = hybrid_keypair
        self.ecdsa = ecdsa_core or ECDSACore()
        self.dilithium = dilithium_core or DilithiumCore()

    def _get_transaction_hash(self, transaction_dict: Dict[str, Any]) -> bytes:
        to_address = transaction_dict.get("to", "0x0000000000000000000000000000000000000000")
        if isinstance(to_address, str):
            to_address = to_address.lower()

        tx = {
            "nonce": transaction_dict.get("nonce", 0),
            "gasPrice": transaction_dict.get("gasPrice", 0),
            "gas": transaction_dict.get("gas", 21000),
            "to": to_address,
            "value": transaction_dict.get("value", 0),
            "data": transaction_dict.get("data", b""),
            "chainId": transaction_dict.get("chainId", 1),
            "v": 0,
            "r": 0,
            "s": 0,
        }

        encoded_tx = rlp.encode([
            tx["nonce"], tx["gasPrice"], tx["gas"],
            tx["to"], tx["value"], tx["data"],
            tx["chainId"], tx["v"], tx["r"], tx["s"]
        ])
        return Web3.keccak(encoded_tx)

    def sign_transaction(self, transaction_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Подписывает транзакцию гибридной подписью (ECDSA + Dilithium)."""
        tx_hash = self._get_transaction_hash(transaction_dict)

        # 1. Классическая подпись ECDSA через eth_keys (совместима с Ethereum)
        classical_sig = self.ecdsa.sign(
            self.keypair.get_classical_private_key(),
            tx_hash
        )  # 65 байт

        # 2. Постквантовая подпись Dilithium через Rust
        pqc_sig = self.dilithium.sign(
            self.keypair.get_pqc_seed(),
            tx_hash
        )

        signature_object = {
            "type": "hybrid-ecdsa-dilithium",   # обновлённый тип
            "classical": "0x" + classical_sig.hex(),
            "pqc": "0x" + pqc_sig.hex(),
            "pqc_public_key": "0x" + self.keypair.get_pqc_public_key().hex(),
        }
        transaction_dict["signature"] = signature_object
        return transaction_dict

    def sign_message(self, message: bytes) -> bytes:
        """Подписывает произвольное сообщение и возвращает только постквантовую подпись."""
        return self.dilithium.sign(self.keypair.get_pqc_seed(), message)

    def verify_hybrid_signature(self, transaction_dict: Dict[str, Any]) -> bool:
        """Верифицирует гибридную подпись транзакции (ECDSA + Dilithium)."""
        signature = transaction_dict.pop("signature", None)
        if not signature:
            return False
        if signature["type"] != "hybrid-ecdsa-dilithium":
            return False

        tx_hash = self._get_transaction_hash(transaction_dict)

        # Извлекаем компоненты подписи
        classical_sig = bytes.fromhex(signature["classical"][2:])
        pqc_sig = bytes.fromhex(signature["pqc"][2:])
        pqc_pub = bytes.fromhex(signature["pqc_public_key"][2:])

        # Верификация ECDSA
        if not self.ecdsa.verify(
            self.keypair.get_classical_public_key(),
            tx_hash,
            classical_sig
        ):
            return False

        # Верификация Dilithium
        return self.dilithium.verify(pqc_pub, tx_hash, pqc_sig)