from sklearn import tree

# [0] - Não é um Ransomware
# [1] - Possível Ransomware
caracteristicas = [
    [3, 2, 2, 1, 0],  # Exemplos de atividade normal
    [2, 0, 15, 0, 0],
    [20, 3, 0, 0, 0],
    [0, 0, 2, 0, 0],
    [0, 0, 2, 0, 5],
    [0, 0, 0, 0, 0],
    [2, 2, 0, 0, 0],
    [0, 2, 0, 20, 0],
    [0, 2, 0, 2, 0],
    [3, 2, 2, 1, 8],  # Exemplos de atividade suspeita (possível ransomware)
    [2, 0, 15, 0, 5],
    [11, 0, 0, 11, 0],
    [0, 10, 0, 2, 30],
    [2, 10, 3, 1, 0],
    [0, 40, 40, 0, 30]
]
rotulos = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1]

# Treinar o classificador de árvore de decisão
classificador = tree.DecisionTreeClassifier()
classificador.fit(caracteristicas, rotulos)


def avaliar(arquivos_criados, arquivos_mods, arquivos_movs, arquivos_delets, arquivos_edits):
    """
    Avalia se uma atividade de arquivos indica possível ransomware.

    Args:
        arquivos_criados (int): Número de arquivos criados.
        arquivos_mods (int): Número de arquivos modificados.
        arquivos_movs (int): Número de arquivos movidos.
        arquivos_delets (int): Número de arquivos deletados.
        arquivos_edits (int): Número de arquivos editados.

    Returns:
        bool: True se for possível ransomware, False caso contrário.
    """
    # Garantir que as entradas sejam inteiros válidos
    try:
        dados_entrada = [int(arquivos_criados), int(arquivos_mods), int(arquivos_movs),
                         int(arquivos_delets), int(arquivos_edits)]
    except ValueError:
        raise ValueError("Todos os argumentos devem ser números inteiros.")

    # Prever usando o modelo treinado
    monitor = classificador.predict([dados_entrada])[0]  # Acessar a primeira previsão
    return bool(monitor)  # Converter 0 para False, 1 para True


# Exemplo de uso
resultado = avaliar(0, 40, 40, 0, 30)  # Deve retornar True (possível ransomware)
print(resultado)