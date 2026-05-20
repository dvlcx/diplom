import os
import sys
import unittest

import oqs

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from mldsa_parser import MLDSAKeyParser


class TestMLDSAKeyParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sig = oqs.Signature("Dilithium3")
        cls.public_key = cls.sig.generate_keypair()
        cls.private_key = cls.sig.export_secret_key()

    @classmethod
    def tearDownClass(cls):
        cls.sig.free()

    def test_parse_public_key(self):
        A, t, rho = MLDSAKeyParser.parse_public_key(self.public_key)

        self.assertEqual(len(A), MLDSAKeyParser.K)
        for i in range(MLDSAKeyParser.K):
            self.assertEqual(len(A[i]), MLDSAKeyParser.L)
            for j in range(MLDSAKeyParser.L):
                self.assertEqual(len(A[i][j]), MLDSAKeyParser.N)
                self.assertIsInstance(A[i][j][0], int)
        self.assertEqual(len(t), MLDSAKeyParser.K)
        for i in range(MLDSAKeyParser.K):
            self.assertEqual(len(t[i]), MLDSAKeyParser.N)
            self.assertIsInstance(t[i][0], int)

        self.assertEqual(len(rho), 1)
        self.assertEqual(len(rho[0]), MLDSAKeyParser.N)
        self.assertIsInstance(rho[0][0], int)

    def test_parse_signature(self):
        message = b"Test message"
        signature = self.sig.sign(message)

        z, h, c = MLDSAKeyParser.parse_signature(signature)

        self.assertEqual(len(z), MLDSAKeyParser.L)
        for i in range(MLDSAKeyParser.L):
            self.assertEqual(len(z[i]), MLDSAKeyParser.N)
            self.assertIsInstance(z[i][0], int)

        self.assertEqual(len(h), MLDSAKeyParser.K)
        for i in range(MLDSAKeyParser.K):
            self.assertEqual(len(h[i]), MLDSAKeyParser.N)
            self.assertIsInstance(h[i][0], int)

        self.assertEqual(len(c), 32)
        self.assertIsInstance(c, bytes)

    def test_verify_original(self):
        message = b"Consistency test"
        signature = self.sig.sign(message)
        valid = self.sig.verify(message, signature, self.public_key)
        self.assertTrue(valid)


if __name__ == "__main__":
    unittest.main()
