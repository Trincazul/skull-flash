import hashlib

def hashgen():
    introhash = input("Digite o texto a ser gerado a Hash: ")
    resultado = hashlib.md5(introhash.encode('utf-8'))

    menuhash = int(input('''##### MENU -  Hash #####
                        1) - MD5
                        2) - SHA1
                        3) - SHA256
                        4) - SHA512
                        Digite o numero do hash a ser gerado: '''))

    if menuhash == 1:
        result = hashlib.md5(introhash.encode('utf-8'))
        print("O Hash MD5 da string: ", introhash, 'é: ', result.hexdigest())
    elif menuhash == 2:
        result = hashlib.sha1(introhash.encode('utf-8'))
        print("O Hash SHA1 da string: ", introhash, 'é: ', result.hexdigest())
    elif menuhash == 3:
        result = hashlib.sha256(introhash.encode('utf-8'))
        print("O Hash SHA256 da string: ", introhash, 'é: ', result.hexdigest())
    elif menuhash == 4:
        result = hashlib.sha512(introhash.encode('utf-8'))
        print("O Hash SHA512 da string: ", introhash, 'é: ', result.hexdigest())
    else:
        print("Selecione uma opção valida !")