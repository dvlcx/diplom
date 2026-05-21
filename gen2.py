Q = 8380417
N = 256
zeta = 1753  # примитивный корень 2N-й степени


# Функция битовой реверсии для 8 бит (0..255)
def bit_reverse(x, bits=8):
    return int("{:08b}".format(x)[::-1], 2)


# Генерируем таблицу корней для прямого NTT (128 элементов)
zetas_forward = [0] * (N // 2)
for i in range(N // 2):
    index = 2 * i + 1  # нечётные индексы 1,3,5,...,255
    rev = bit_reverse(index, 8)  # битовая реверсия в пределах 0..255
    zetas_forward[i] = pow(zeta, rev, Q)

# Обратные корни (мультипликативные обратные в поле)
zetas_inverse = [pow(z, Q - 2, Q) for z in zetas_forward]

# При желании расширяем до длины N, дублируя или дополняя нулями
# (в стандартных реализациях длина таблицы именно 128)
psi_rev = zetas_forward + [0] * (N - len(zetas_forward))
psi_inv_rev = zetas_inverse + [0] * (N - len(zetas_inverse))

# Вывод в формате Solidity
print("uint256[256] psi_rev = [")
for i in range(0, N, 8):
    row = ", ".join(str(psi_rev[i + j]) for j in range(8))
    print("    " + row + ("," if i + 8 < N else ""))
print("];\n")

print("uint256[256] psi_inv_rev = [")
for i in range(0, N, 8):
    row = ", ".join(str(psi_inv_rev[i + j]) for j in range(8))
    print("    " + row + ("," if i + 8 < N else ""))
print("];")
