# import nmap
import os

def mapping():
    pass

def pingmenu():
    print('''Selecione o sistema operacional
                1) - Mac ou Linux
                2) - Windows''')
    sisop = int(input())
    ping_host = input("Digite o IP ou Host a ser verificado: ")
    if sisop == 1:
        print("#" * 60)
        os.system(f'ping -c 6 {ping_host}')
    elif sisop == 2:
        print("#" * 60)
        os.system(f'ping -n 6 {ping_host}')
    else:
        print('Opção informada incorreta !')

def main():
    option = int(input('''Selecione -> 1 para mapeamento de rede:
Selecione -> 2 para fazer um ping simples no IP:  '''))
    if option == 1:
        print('Numero 1 foi selecionado')
    elif option == 2:
        print('Numero 2 foi selecionado')
        pingmenu()
    else:
        print('Opção errada')
