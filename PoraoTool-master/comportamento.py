from sklearn import tree

caracteristicas = [
    [3, 2, 2, 1, 0], [2, 0, 15, 0, 0], [20, 3, 0, 0, 0], [0, 0, 2, 0, 0],
    [0, 0, 2, 0, 5], [0, 0, 0, 0, 0], [2, 2, 0, 0, 0], [0, 2, 0, 20, 0],
    [0, 2, 0, 2, 0], [3, 2, 2, 1, 8], [2, 0, 15, 0, 5], [11, 0, 0, 11, 0],
    [0, 10, 0, 2, 30], [2, 10, 3, 1, 0], [0, 40, 40, 0, 30]
]
rotulos = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1]

classificador = tree.DecisionTreeClassifier()
classificador.fit(caracteristicas, rotulos)


def avaliar(arquivos_criados, arquivos_mods, arquivos_movs, arquivos_delets, arquivos_edits):
    try:
        dados_entrada = [int(arquivos_criados), int(arquivos_mods), int(arquivos_movs),
                         int(arquivos_delets), int(arquivos_edits)]
    except ValueError:
        raise ValueError("Todos os argumentos devem ser números inteiros.")
    monitor = classificador.predict([dados_entrada])[0]
    return bool(monitor)