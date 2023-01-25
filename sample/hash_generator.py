import hashlib

def hashgen():
    introhash = input("Digite o texto a ser gerado a Hash: ")

    hash_options = {
        1: hashlib.md5,
        2: hashlib.sha1,
        3: hashlib.sha256,
        4: hashlib.sha512
    }

    menuhash = int(input('''Menu de Criptografia, Hash
                        1) - MD5
                        2) - SHA1
                        3) - SHA256
                        4) - SHA512
                        Digite o numero do hash a ser gerado: '''))

    if menuhash in hash_options:
        result = hash_options[menuhash](introhash.encode('utf-8'))
        print(f"O {hash_options[menuhash].__name__} hash do texto: {introhash} é: {result.hexdigest()}")
    else:
        print("Selecione uma opção valida")