import oqs
from Crypto.Hash import SHA512
from Crypto.Signature import eddsa
from web3 import Web3


class HybridSigner:
    """Класс для создания и верификации гибридных подписей."""

    def __init__(self, hybrid_keypair):
        self.keypair = hybrid_keypair

    def _get_transaction_hash(self, transaction_dict):
        """
        Преобразует словарь транзакции в каноническое байтовое представление
        и вычисляет его хэш для подписания.
        """
        # Нормализуем адрес получателя
        to_address = transaction_dict.get(
            "to", "0x0000000000000000000000000000000000000000"
        )

        # Если адрес — строка, приводим к нижнему регистру для совместимости
        if isinstance(to_address, str):
            to_address = to_address.lower()

        # Подготавливаем транзакцию для RLP
        # Для простоты используем структуру, аналогичную типу 0 (legacy)
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

        # Сериализуем в RLP
        from rlp import encode

        encoded_tx = encode(
            [
                tx["nonce"],
                tx["gasPrice"],
                tx["gas"],
                tx["to"],
                tx["value"],
                tx["data"],
                tx["chainId"],
                tx["v"],
                tx["r"],
                tx["s"],
            ]
        )

        # Вычисляем хэш (keccak256)
        tx_hash = Web3.keccak(encoded_tx)

        return tx_hash

    def sign_transaction(self, transaction_dict):
        """
        Подписывает транзакцию гибридной подписью.
        Возвращает транзакцию с добавленным полем signature.
        """
        # Получаем хэш транзакции для подписания
        tx_hash = self._get_transaction_hash(transaction_dict)

        # 1. Классическая подпись Ed25519
        # Для HashEdDSA используем SHA512 от хэша транзакции
        h = SHA512.new(tx_hash)
        signer = eddsa.new(self.keypair.classical_private, "rfc8032")
        classical_sig = signer.sign(h)  # 64 байта

        # 2. Постквантовая подпись ML-DSA-65
        dilithium = oqs.Signature("Dilithium3", self.keypair.pqc_private)
        pqc_sig = dilithium.sign(tx_hash)  # 3293 байта
        dilithium.free()

        # 3. Формируем объект подписи согласно модели данных
        signature_object = {
            "type": "hybrid-ed25519-mldsa65",
            "classical": "0x" + classical_sig.hex(),
            "pqc": "0x" + pqc_sig.hex(),
            "pqc_public_key": "0x" + self.keypair.pqc_public.hex(),
        }

        # Добавляем подпись в транзакцию
        transaction_dict["signature"] = signature_object

        return transaction_dict

    def verify_hybrid_signature(self, transaction_dict):
        """
        Верифицирует гибридную подпись транзакции.
        Используется для off-chain проверки.
        """
        # Извлекаем подпись и удаляем её из данных для верификации
        signature = transaction_dict.pop("signature", None)
        if not signature:
            return False

        # Проверяем тип подписи
        if signature["type"] != "hybrid-ed25519-mldsa65":
            return False

        # Получаем хэш транзакции
        tx_hash = self._get_transaction_hash(transaction_dict)

        # Восстанавливаем подписи из hex
        classical_sig = bytes.fromhex(signature["classical"][2:])
        pqc_sig = bytes.fromhex(signature["pqc"][2:])
        pqc_pub = bytes.fromhex(signature["pqc_public_key"][2:])

        # 1. Верификация Ed25519
        h = SHA512.new(tx_hash)
        verifier = eddsa.new(self.keypair.classical_public, "rfc8032")
        try:
            verifier.verify(h, classical_sig)
        except ValueError:
            return False

        # 2. Верификация ML-DSA-65
        dilithium = oqs.Signature("Dilithium3")
        is_valid = dilithium.verify(tx_hash, pqc_sig, pqc_pub)
        dilithium.free()

        return is_valid
