Q = 8380417
N = 256
# Примитивный корень 2N-й степени из единицы (из спецификации Dilithium)
zeta = 1753

# Вычисляем psi = zeta^2
psi = pow(zeta, 2, Q)
psi_inv = pow(psi, Q - 2, Q)

# Вычисляем степени psi и psi_inv в прямом порядке
powers_psi = [1] * (N)
for i in range(1, N):
    powers_psi[i] = (powers_psi[i - 1] * psi) % Q

powers_psi_inv = [1] * (N)
for i in range(1, N):
    powers_psi_inv[i] = (powers_psi_inv[i - 1] * psi_inv) % Q


# Битовая реверсия для индексов (размер N)
def bit_reverse(i, bits):
    rev = 0
    for b in range(bits):
        rev = (rev << 1) | ((i >> b) & 1)
    return rev


bits = 8  # log2(256)
psi_rev = [0] * N
psi_inv_rev = [0] * N
for i in range(N):
    rev = bit_reverse(i, bits)
    psi_rev[i] = powers_psi[rev]
    psi_inv_rev[i] = powers_psi_inv[rev]

# Вывод в формате Solidity
print("uint256[256] psi_rev = [")
for i in range(0, N, 8):
    print("    " + ", ".join(str(x) for x in psi_rev[i : i + 8]) + ",")
print("];")
print()
print("uint256[256] psi_inv_rev = [")
for i in range(0, N, 8):
    print("    " + ", ".join(str(x) for x in psi_inv_rev[i : i + 8]) + ",")
print("];")
