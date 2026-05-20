import hashlib
import os
import sys
import tempfile
import unittest
from unittest.runner import TextTestResult

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from hybrid_key_pair import HybridKeyPair


class TestHybridKeyPair(unittest.TestCase):
    keypair: HybridKeyPair

    def setUp(self) -> None:
        """Подготовка перед каждым тестом"""
        print(f"\n--- Запуск теста: {self._testMethodName} ---")
        self.keypair = HybridKeyPair()
        self.keypair.generate()
        # Убеждаемся, что адрес сгенерирован
        assert self.keypair.address is not None, "Address should be generated"
        assert self.keypair.classical_public is not None, (
            "Classical public key should be generated"
        )
        assert self.keypair.pqc_public is not None, "PQC public key should be generated"

    def test_generation_success(self) -> None:
        """Тест успешной генерации ключей"""
        self.assertIsNotNone(self.keypair.classical_private)
        self.assertIsNotNone(self.keypair.classical_public)
        self.assertIsNotNone(self.keypair.pqc_private)
        self.assertIsNotNone(self.keypair.pqc_public)
        self.assertIsNotNone(self.keypair.address)

        address = self.keypair.address
        assert address is not None
        self.assertTrue(address.startswith("0x"))

        # Проверяем длину адреса (0x + 39 байт * 2 hex символа = 0x + 78)
        expected_hex_length = 78
        self.assertEqual(len(address) - 2, expected_hex_length)

        print(f"✓ Адрес сгенерирован: {address}")
        print(f"✓ Длина адреса: {len(address)} символов")

    def test_address_consistency(self) -> None:
        """Тест согласованности адреса"""
        # Генерируем адрес повторно
        address2 = self.keypair._generate_address()
        self.assertEqual(self.keypair.address, address2)

        # Проверяем контрольную сумму
        address = self.keypair.address
        assert address is not None
        address_bytes = bytes.fromhex(address[2:])
        version = address_bytes[0:1]
        algo_id = address_bytes[1:3]
        pub_hash = address_bytes[3:35]
        checksum = address_bytes[35:39]

        # Пересчитываем контрольную сумму
        expected_checksum = hashlib.sha256(
            hashlib.sha256(version + algo_id + pub_hash).digest()
        ).digest()[:4]

        self.assertEqual(checksum, expected_checksum)
        print("✓ Контрольная сумма адреса корректна")

    def test_key_types(self) -> None:
        """Тест типов ключей"""
        self.assertTrue(hasattr(self.keypair.classical_private, "export_key"))

        pqc_private = self.keypair.pqc_private
        pqc_public = self.keypair.pqc_public
        assert pqc_private is not None
        assert pqc_public is not None
        self.assertIsInstance(pqc_private, bytes)
        self.assertIsInstance(pqc_public, bytes)

        print("✓ Типы ключей корректны")
        print(
            f"  - PQC приватный ключ: {type(pqc_private).__name__}, длина: {len(pqc_private)} байт"
        )
        print(
            f"  - PQC публичный ключ: {type(pqc_public).__name__}, длина: {len(pqc_public)} байт"
        )

    def test_save_and_load(self) -> None:
        """Тест сохранения и загрузки ключей"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Сохраняем
            self.keypair.save_to_file(tmpdir)
            print(f"✓ Ключи сохранены в {tmpdir}")

            # Загружаем
            loaded = HybridKeyPair.load_from_file(tmpdir)
            print(f"✓ Ключи загружены из {tmpdir}")

            # Сравниваем адреса
            self.assertEqual(self.keypair.address, loaded.address)

            # Сравниваем публичные ключи
            classical_pub = self.keypair.classical_public
            loaded_classical_pub = loaded.classical_public
            assert classical_pub is not None
            assert loaded_classical_pub is not None

            orig_classical_pub = classical_pub.export_key(format="raw")
            loaded_classical_pub_bytes = loaded_classical_pub.export_key(format="raw")
            self.assertEqual(orig_classical_pub, loaded_classical_pub_bytes)

            # Сравниваем PQC публичные ключи
            self.assertEqual(self.keypair.pqc_public, loaded.pqc_public)

            print("✓ Сохраненные и загруженные ключи совпадают")

    def test_error_handling(self) -> None:
        """Тест обработки ошибок"""
        # Попытка сохранить без генерации
        empty_keypair = HybridKeyPair()
        with self.assertRaises(ValueError):
            empty_keypair.save_to_file()

        # Попытка получить ключи без генерации
        with self.assertRaises(ValueError):
            empty_keypair.get_classical_private_key()

        with self.assertRaises(ValueError):
            empty_keypair.get_pqc_private_key()

        print("✓ Обработка ошибок работает корректно")

    def test_getters(self) -> None:
        """Тест геттеров"""
        classical_priv = self.keypair.get_classical_private_key()
        classical_pub = self.keypair.get_classical_public_key()
        pqc_priv = self.keypair.get_pqc_private_key()
        pqc_pub = self.keypair.get_pqc_public_key()

        self.assertEqual(classical_priv, self.keypair.classical_private)
        self.assertEqual(classical_pub, self.keypair.classical_public)
        self.assertEqual(pqc_priv, self.keypair.pqc_private)
        self.assertEqual(pqc_pub, self.keypair.pqc_public)

        print("✓ Геттеры возвращают корректные значения")


# Запуск unit-тестов с детальным выводом
def run_unit_tests() -> TextTestResult:
    print("=" * 60)
    print("НАЧАЛО ТЕСТИРОВАНИЯ HYBRID KEY PAIR")
    print("=" * 60)

    # Создаем тестовый набор
    suite = unittest.TestLoader().loadTestsFromTestCase(TestHybridKeyPair)

    # Запускаем с verbosity=2 для детального вывода
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Выводим итоговую статистику
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
        if result.failures:
            print("\nПадения:")
            for failure in result.failures:
                print(f"  - {failure[0]}")
        if result.errors:
            print("\nОшибки:")
            for error in result.errors:
                print(f"  - {error[0]}")

    return result


if __name__ == "__main__":
    result = run_unit_tests()
    # Возвращаем код ошибки если тесты не прошли
    sys.exit(0 if result.wasSuccessful() else 1)
