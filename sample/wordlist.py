import itertools

def wordlist():
    string = input("String a ser permutada: ")
    resultado = itertools.permutations(string, len(string))
    for i in resultado:
        print(''.join(i))

def wordlist_test():
    string = input("String a ser permutada: ")
    size = int(input("Tamanho da permutação (digite 0 para usar tamanho da string): "))
    if size == 0:
        size = len(string)
    repeat = input("Permutações com repetição? (s/n)")
    if repeat == 's':
        repeat = True
    else:
        repeat = False
    save_file = input("Salvar resultado em arquivo? (s/n)")
    if save_file == 's':
        filename = input("Nome do arquivo: ")
    include = input("Incluir caracteres específicos? (s/n)")
    if include == 's':
        include_list = input("Lista de caracteres (separados por vírgula): ").split(',')
        string += ''.join(include_list)
    exclude = input("Excluir caracteres específicos? (s/n)")
    if exclude == 's':
        exclude_list = input("Lista de caracteres (separados por vírgula): ").split(',')
        for char in exclude_list:
            string = string.replace(char, '')
    prohibited = input("Excluir palavras proibidas? (s/n)")
    if prohibited == 's':
        prohibited_list = input("Lista de palavras (separadas por vírgula): ").split(',')
    lexicographic = input("Permutações em ordem lexicográfica? (s/n)")
    if lexicographic == 's':
        resultado = itertools.permutations(sorted(string), size, repeat)
    else:
        resultado = itertools.permutations(string, size, repeat)
    if prohibited == 's':
        resultado = [x for x in resultado if ''.join(x) not in prohibited_list]
    if save_file == 's':
        with open(filename, 'w') as f:
            for i in resultado:
                f.write(''.join(i) + '\n')
    else:
        for i in resultado:
            print(''.join(i))
