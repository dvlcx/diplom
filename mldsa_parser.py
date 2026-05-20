import struct
from typing import List, Tuple

from dilithium_py.dilithium import Dilithium3


class MLDSAKeyParser:
    Q = 8380417
    N = 256
    K = 6
    L = 5
    GAMMA1 = 131072

    @classmethod
    def parse_public_key(
        cls, pk_bytes: bytes
    ) -> Tuple[List[List[List[int]]], List[List[int]], List[List[int]]]:
        # Получаем rho и t1
        rho, t1 = Dilithium3._unpack_pk(pk_bytes)

        # Генерируем матрицу A
        A = Dilithium3._expand_matrix_from_seed(rho)

        # Преобразуем A в список списков списков
        A_list = []
        for i in range(cls.K):
            row = []
            for j in range(cls.L):
                # A[i, j] — это полином, который может быть объектом Vector или массивом
                poly = A[i, j]
                # Приводим каждый элемент к int (на случай, если это другой тип)
                poly_list = [int(poly[idx]) % cls.Q for idx in range(cls.N)]
                row.append(poly_list)
            A_list.append(row)

        # Преобразуем t1 в список списков
        t_list = []
        for i in range(cls.K):
            poly = t1[i, 0]
            poly_list = [int(poly[idx]) % cls.Q for idx in range(cls.N)]
            t_list.append(poly_list)

        # Преобразуем seed в полином (первый элемент – seed, остальные 0)
        seed_int = int.from_bytes(rho, byteorder="big")
        rho_poly = [0] * cls.N
        rho_poly[0] = seed_int % cls.Q
        rho_list = [rho_poly]

        return A_list, t_list, rho_list

    @classmethod
    def parse_signature(
        cls, sig_bytes: bytes
    ) -> Tuple[List[List[int]], List[List[int]], bytes]:
        # Распаковываем подпись
        c, z, h = Dilithium3._unpack_sig(sig_bytes)

        # Преобразуем z
        z_list = []
        for i in range(cls.L):
            poly = z[i, 0]
            poly_list = [int(poly[idx]) % cls.Q for idx in range(cls.N)]
            z_list.append(poly_list)

        # Преобразуем h (подсказки)
        h_list = []
        for i in range(cls.K):
            poly = h[i, 0]
            poly_list = [
                int(poly[idx]) for idx in range(cls.N)
            ]  # подсказки не по модулю Q
            h_list.append(poly_list)

        # c уже в bytes
        return z_list, h_list, c
