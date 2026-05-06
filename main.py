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
# x = Valor que vamos rotacionar
# y = Quantidade de bits que vamos rotacionar
def ROR(x, y):
    # Máscara de 32 bits com todos os bits ligados.
    # Referência: https://mathmonks.com/wp-content/uploads/2024/04/Hexadecimal-to-Binary.jpg
    # Pela tabela hexadecimal -> binário, cada dígito hexadecimal representa 4 bits.
    # Isso acontece porque 4 bits permitem 2^4 = 16 combinações, exatamente a quantidade
    # de símbolos hexadecimais possíveis: 0, 1, 2, ..., 9, a, b, c, d, e, f.
    # O dígito "f" representa o maior valor hexadecimal e em binário vale 1111,
    # ou seja, mantém os 4 bits daquele bloco ligados.
    # Portanto: 0xffffffff = 8 dígitos "f" * 4 bits = 32 bits ligados.
    mask_32 = 0xffffffff
    # Normalizamos a quantidade de rotações para o intervalo de 0 a 31.
    # Como estamos trabalhando com 32 bits, rotacionar 32 vezes volta ao valor original.
    # Por isso usamos o resto da divisão por 32: qualquer valor maior que 31
    # equivale a uma rotação menor dentro desse ciclo, como em um relógio.
    # Exemplo: rotacionar 33 vezes é o mesmo que rotacionar 1 vez.
    rot = y % 32
    # Limitamos x para trabalhar apenas com 32 bits.
    # O operador & faz uma comparação bit a bit entre x e a máscara.
    # Como mask_32 = 0xffffffff possui os 32 bits ligados, cada bit de x
    # dentro desse intervalo é preservado.
    # Bits que estiverem acima dos 32 bits são descartados, pois não têm
    # uma posição correspondente ligada na máscara.
    # Exemplo:
    #   0x123456789 & 0xffffffff = 0x23456789
    # Ou seja, mantemos somente os últimos 32 bits de x.
    x_32 = x & mask_32

    # Deslocamos os bits de x_32 para a direita pela quantidade definida em rot.
    # No shift para a direita (>>), entram zeros à esquerda e os bits que passam
    # do limite à direita são descartados temporariamente.
    # Exemplo com rot = 8:
    #   0x01234567 >> 8 = 0x00012345
    #   [01][23][45][67] -> [00][01][23][45]
    # Na rotação completa, os bits descartados aqui serão recuperados pela parte
    # esquerda da fórmula.
    right_part = x_32 >> rot

    # Parte complementar da rotação para a direita.
    # Deslocamos x_32 para a esquerda por 32 - rot posições para fazer
    # os bits que saíram pela direita voltarem para o começo.
    # A máscara garante que, após o deslocamento, apenas os 32 bits finais
    # sejam mantidos.
    # Exemplo com rot = 8:
    #   [01][23][45][67] << 24 = [67][00][00][00] dentro de 32 bits.
    left_part = (x_32 << (32 - rot)) & mask_32

    # Juntamos as duas partes da rotação usando OR bit a bit.
    # right_part contém os bits deslocados para a direita.
    # left_part contém os bits que deram a volta e foram para a esquerda.
    # A máscara final garante que o resultado continue limitado a 32 bits.
    # Exemplo:
    #   right_part = [00][01][23][45]
    #   left_part  = [67][00][00][00]
    #   resultado  = [67][01][23][45]
    return (right_part | left_part) & mask_32


# Escolhe bits de y ou z com base em x (função Ch do SHA-256).
def Ch(x, y, z):
    # Usa x como uma máscara para escolher bits entre y e z.
    #
    # Para cada bit:
    # - se o bit de x for 1, escolhe o bit de y;
    # - se o bit de x for 0, escolhe o bit de z.
    #
    # O operador ^ é XOR:
    # - retorna 1 quando os bits são diferentes;
    # - retorna 0 quando os bits são iguais.
    #
    # O operador & é AND:
    # - retorna 1 apenas quando os dois bits são 1;
    # - caso contrário, retorna 0.
    #
    # Na expressão z ^ (x & (y ^ z)):
    # 1. y ^ z descobre onde y e z são diferentes;
    # 2. x & (...) usa x como máscara para decidir quais diferenças importam;
    # 3. z ^ (...) aplica essas diferenças sobre z, transformando os bits escolhidos em y.
    return z ^ (x & (y ^ z))


# Retorna o bit majoritário entre x, y e z (função Maj do SHA-256).
def Maj(x, y, z):
    # Usa x, y e z para descobrir qual bit aparece em maioria.
    #
    # Para cada posição de bit:
    # - se pelo menos dois entre x, y e z forem 1, o resultado será 1;
    # - se pelo menos dois entre x, y e z forem 0, o resultado será 0.
    #
    # Exemplo:
    #   x = 1
    #   y = 0
    #   z = 1
    #
    # Como temos dois bits 1, a maioria é 1.
    #
    # Na expressão ((x | y) & z) | (x & y):
    # 1. x | y verifica se x ou y possuem bit 1;
    # 2. (x | y) & z verifica se z também participa de uma maioria com x ou y;
    # 3. x & y verifica se x e y já formam maioria sozinhos;
    # 4. o resultado final junta essas possibilidades.
    #
    # Em resumo:
    # essa função retorna 1 quando existe maioria de bits 1
    # e retorna 0 quando a maioria é de bits 0.
    return ((x | y) & z) | (x & y)


# Atalho para rotação à direita.
def S(x, n):
    return ROR(x, n)


# Shift lógico para a direita em n bits.
def R(x, n):
    # Usamos a mesma máscara de 32 bits explicada na função ROR.
    # Ela garante que x fique limitado a 32 bits.
    mask_32 = 0xffffffff

    # Mantém apenas os últimos 32 bits de x.
    x_32 = x & mask_32

    # Desloca os bits para a direita em n posições.
    # Diferente da rotação, os bits que saem pela direita são descartados
    # e entram zeros pela esquerda.
    return x_32 >> n


# Função Sigma0 usada na etapa principal de compressão.
def Sigma0(x):
    # Aplicamos a função S, que é uma abstração da função ROR,
    # rotacionando x para a direita em 2, 13 e 22 bits.
    # Depois combinamos os resultados usando XOR (^).
    #
    # Aplica rotações fixas definidas pelo SHA-256.
    # Os valores 2, 13 e 22 fazem parte da especificação do algoritmo
    # Eles ajudam a misturar melhor os bits de x.
    return S(x, 2) ^ S(x, 13) ^ S(x, 22)


# Função Sigma1 usada na etapa principal de compressão.
def Sigma1(x):
    # Aplicamos a função S, que é uma abstração da função ROR,
    # rotacionando x para a direita em 6, 11 e 25 bits.
    # Depois combinamos os resultados usando XOR (^).
    #
    # Os valores 6, 11 e 25 são constantes fixas definidas pelo SHA-256.
    # Eles ajudam a misturar melhor os bits de x.
    return S(x, 6) ^ S(x, 11) ^ S(x, 25)


# Função Gamma0 (sigma0 minúscula) usada na expansão da mensagem.
def Gamma0(x):
    # Aplicamos a função S, que é uma abstração da função ROR,
    # rotacionando x para a direita em 7 e 18 bits.
    # Também aplicamos a função R, que faz shift lógico para a direita em 3 bits.
    # Depois combinamos os resultados usando XOR (^).
    #
    # Os valores 7, 18 e 3 são constantes fixas definidas pelo SHA-256.
    # Eles ajudam a misturar melhor os bits de x.
    return S(x, 7) ^ S(x, 18) ^ R(x, 3)


# Função Gamma1 (sigma1 minúscula) usada na expansão da mensagem.
def Gamma1(x):
    # Aplicamos a função S, que é uma abstração da função ROR,
    # rotacionando x para a direita em 17 e 19 bits.
    # Também aplicamos a função R, que faz shift lógico para a direita em 10 bits.
    # Depois combinamos os resultados usando XOR (^).
    #
    # Os valores 17, 19 e 10 são constantes fixas definidas pelo SHA-256.
    # Eles ajudam a misturar melhor os bits de x.
    return S(x, 17) ^ S(x, 19) ^ R(x, 10)