import os
import sys
import time
import unittest
from unittest.runner import TextTestResult

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from hybrid_key_pair import HybridKeyPair
from hybrid_signer import HybridSigner


class TestHybridSigner(unittest.TestCase):
    """Тесты для класса HybridSigner"""

    def setUp(self) -> None:
        """Подготовка перед каждым тестом"""
        print(f"\n--- Запуск теста: {self._testMethodName} ---")
        self.keypair = HybridKeyPair()
        self.keypair.generate()
        self.signer = HybridSigner(self.keypair)

        self.test_transaction = {
            "nonce": 1,
            "gasPrice": 1000000000,
            "gas": 21000,
            "to": "0x742d35Cc6634C0532925a3b844Bc9e943fFf9eE",
            "value": 1000000000000000000,
            "data": b"",
            "chainId": 1,
        }

        assert self.keypair.address is not None
        assert self.keypair.classical_private is not None
        assert self.keypair.pqc_private is not None

    def test_signer_initialization(self) -> None:
        """Тест инициализации"""
        self.assertIsNotNone(self.signer)
        self.assertEqual(self.signer.keypair, self.keypair)
        print("✓ Подписывающий объект успешно инициализирован")

    def test_get_transaction_hash(self) -> None:
        """Тест получения хэша транзакции"""
        tx_hash = self.signer._get_transaction_hash(self.test_transaction)

        self.assertIsNotNone(tx_hash)
        self.assertIsInstance(tx_hash, bytes)
        self.assertEqual(len(tx_hash), 32)

        # Проверяем, что для одинаковых транзакций хэши совпадают
        tx_hash2 = self.signer._get_transaction_hash(self.test_transaction)
        self.assertEqual(tx_hash, tx_hash2)

        # Проверяем, что для разных транзакций хэши разные
        modified_tx = self.test_transaction.copy()
        modified_tx["nonce"] = 2
        tx_hash3 = self.signer._get_transaction_hash(modified_tx)
        self.assertNotEqual(tx_hash, tx_hash3)

        print(f"✓ Хэш транзакции: {tx_hash.hex()[:32]}...")

    def test_sign_transaction(self) -> None:
        """Тест подписания транзакции"""
        signed_tx = self.signer.sign_transaction(self.test_transaction.copy())

        # Проверяем структуру подписи
        self.assertIn("signature", signed_tx)
        signature = signed_tx["signature"]
        self.assertEqual(signature["type"], "hybrid-ed25519-mldsa65")
        self.assertIn("classical", signature)
        self.assertIn("pqc", signature)
        self.assertIn("pqc_public_key", signature)

        # Проверяем форматы
        self.assertTrue(signature["classical"].startswith("0x"))
        self.assertTrue(signature["pqc"].startswith("0x"))
        self.assertTrue(signature["pqc_public_key"].startswith("0x"))

        # Проверяем длины
        classical_sig_bytes = bytes.fromhex(signature["classical"][2:])
        pqc_sig_bytes = bytes.fromhex(signature["pqc"][2:])
        self.assertEqual(len(classical_sig_bytes), 64)  # Ed25519
        self.assertGreater(len(pqc_sig_bytes), 3000)  # ML-DSA-65

        print(
            f"✓ Транзакция подписана (Ed25519: {len(classical_sig_bytes)} байт, ML-DSA-65: {len(pqc_sig_bytes)} байт)"
        )

    def test_verify_valid_signature(self) -> None:
        """Тест верификации корректной подписи"""
        signed_tx = self.signer.sign_transaction(self.test_transaction.copy())
        is_valid = self.signer.verify_hybrid_signature(signed_tx.copy())
        self.assertTrue(is_valid)
        print("✓ Корректная подпись успешно верифицирована")

    def test_verify_invalid_signature(self) -> None:
        """Тест верификации некорректной подписи"""
        # Подписываем и изменяем транзакцию
        signed_tx = self.signer.sign_transaction(self.test_transaction.copy())
        signed_tx["value"] = 2000000000000000000  # Меняем значение

        is_valid = self.signer.verify_hybrid_signature(signed_tx.copy())
        self.assertFalse(is_valid)
        print("✓ Измененная транзакция корректно отклонена")

    def test_verify_wrong_type(self) -> None:
        """Тест с неправильным типом подписи"""
        signed_tx = self.signer.sign_transaction(self.test_transaction.copy())
        signed_tx["signature"]["type"] = "invalid-type"

        is_valid = self.signer.verify_hybrid_signature(signed_tx.copy())
        self.assertFalse(is_valid)
        print("✓ Неправильный тип подписи корректно отклонен")

    def test_verify_no_signature(self) -> None:
        """Тест без подписи"""
        is_valid = self.signer.verify_hybrid_signature(self.test_transaction.copy())
        self.assertFalse(is_valid)
        print("✓ Отсутствие подписи корректно обнаружено")

    def test_verify_wrong_classical_sig(self) -> None:
        """Тест с измененной классической подписью"""
        signed_tx = self.signer.sign_transaction(self.test_transaction.copy())

        # Изменяем классическую подпись
        classical_sig = signed_tx["signature"]["classical"]
        classical_bytes = bytes.fromhex(classical_sig[2:])
        modified_bytes = bytearray(classical_bytes)
        modified_bytes[0] ^= 0xFF
        signed_tx["signature"]["classical"] = "0x" + bytes(modified_bytes).hex()

        is_valid = self.signer.verify_hybrid_signature(signed_tx.copy())
        self.assertFalse(is_valid)
        print("✓ Измененная классическая подпись корректно отклонена")

    def test_verify_wrong_pqc_sig(self) -> None:
        """Тест с измененной PQC подписью"""
        signed_tx = self.signer.sign_transaction(self.test_transaction.copy())

        # Изменяем PQC подпись
        pqc_sig = signed_tx["signature"]["pqc"]
        pqc_bytes = bytes.fromhex(pqc_sig[2:])
        modified_bytes = bytearray(pqc_bytes)
        modified_bytes[0] ^= 0xFF
        signed_tx["signature"]["pqc"] = "0x" + bytes(modified_bytes).hex()

        is_valid = self.signer.verify_hybrid_signature(signed_tx.copy())
        self.assertFalse(is_valid)
        print("✓ Измененная PQC подпись корректно отклонена")

    def test_different_keys(self) -> None:
        """Тест с разными ключами"""
        other_keypair = HybridKeyPair()
        other_keypair.generate()
        other_signer = HybridSigner(other_keypair)

        signed_tx = self.signer.sign_transaction(self.test_transaction.copy())
        is_valid = other_signer.verify_hybrid_signature(signed_tx.copy())
        self.assertFalse(is_valid)
        print("✓ Подписи от разных ключей корректно не верифицируются")

    def test_minimal_transaction(self) -> None:
        """Тест с минимальной транзакцией"""
        minimal_tx = {
            "to": "0x742d35Cc6634C0532925a3b844Bc9e943fFf9eE",
            "chainId": 1,
        }

        tx_hash = self.signer._get_transaction_hash(minimal_tx)
        self.assertIsNotNone(tx_hash)

        signed_tx = self.signer.sign_transaction(minimal_tx.copy())
        self.assertIn("signature", signed_tx)

        is_valid = self.signer.verify_hybrid_signature(signed_tx.copy())
        self.assertTrue(is_valid)
        print("✓ Минимальная транзакция успешно обработана")

    def test_performance(self) -> None:
        """Тест производительности"""
        iterations = 5

        # Тест подписания
        start = time.time()
        for _ in range(iterations):
            self.signer.sign_transaction(self.test_transaction.copy())
        sign_time = (time.time() - start) / iterations * 1000

        # Тест верификации
        signed_tx = self.signer.sign_transaction(self.test_transaction.copy())
        start = time.time()
        for _ in range(iterations):
            self.signer.verify_hybrid_signature(signed_tx.copy())
        verify_time = (time.time() - start) / iterations * 1000

        print(f"✓ Среднее время подписания: {sign_time:.2f} мс")
        print(f"✓ Среднее время верификации: {verify_time:.2f} мс")

        self.assertLess(sign_time, 500, "Подписание слишком медленное")
        self.assertLess(verify_time, 500, "Верификация слишком медленная")


# Запуск тестов
def run_tests() -> TextTestResult:
    print("=" * 60)
    print("НАЧАЛО ТЕСТИРОВАНИЯ HYBRID SIGNER")
    print("=" * 60)

    suite = unittest.TestLoader().loadTestsFromTestCase(TestHybridSigner)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 60)
    print("РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ")
    print("=" * 60)
    print(f"Запущено тестов: {result.testsRun}")
    print(f"Успешно: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Ошибок: {len(result.errors)}")
    print(f"Падений: {len(result.failures)}")

    if result.wasSuccessful():
        print("\n✅ ВСЕ ТЕСТЫ ПРОШЛИ УСПЕШНО!")
    else:
        print("\n❌ НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОШЛИ")

    return result


if __name__ == "__main__":
    result = run_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
