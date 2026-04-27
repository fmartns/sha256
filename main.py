# Biblioteca nativa do Python para converter bytes em valores binários
import struct

SHA_BLOCKSIZE = 64
SHA_DIGESTSIZE = 32

def new_shaobject():
    return {
        'digest': [0]*8, # Cria uma lista com 8 posições, todas começando em zero.
        'count_lo': 0,
        'count_hi': 0,
        'data': [0]* SHA_BLOCKSIZE,
        'local': 0,
        'digestsize': 0
    }

# Rotaciona x para a direita em y bits (considerando 32 bits).
def ROR(x, y):
    mask_32 = 0xffffffff
    rot = y % 32
    x_32 = x & mask_32

    right_part = x_32 >> rot
    left_part = (x_32 << (32 - rot)) & mask_32

    return (right_part | left_part) & mask_32


# Escolhe bits de y ou z com base em x (função Ch do SHA-256).
def Ch(x, y, z):
    return z ^ (x & (y ^ z))


# Retorna o bit majoritário entre x, y e z (função Maj do SHA-256).
def Maj(x, y, z):
    return ((x | y) & z) | (x & y)


# Atalho para rotação à direita.
def S(x, n):
    return ROR(x, n)


# Shift lógico para a direita em n bits.
def R(x, n):
    return (x & 0xffffffff) >> n


# Função Sigma0 usada na etapa principal de compressão.
def Sigma0(x):
    return S(x, 2) ^ S(x, 13) ^ S(x, 22)


# Função Sigma1 usada na etapa principal de compressão.
def Sigma1(x):
    return S(x, 6) ^ S(x, 11) ^ S(x, 25)


# Função Gamma0 (sigma0 minúscula) usada na expansão da mensagem.
def Gamma0(x):
    return S(x, 7) ^ S(x, 18) ^ R(x, 3)


# Função Gamma1 (sigma1 minúscula) usada na expansão da mensagem.
def Gamma1(x):
    return S(x, 17) ^ S(x, 19) ^ R(x, 10)
