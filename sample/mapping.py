# import nmap
import os

def main():
    print('''Selecione o sistema operacional
                1) - Mac ou Linux
                2) - Windows''')
    sisop = int(input())
    ping_host = input("Digite o IP ou Host a ser verificado: ")
    if sisop == 1:
        macping(ping_host)
    elif sisop == 2:
        winping(ping_host)
    else:
        print('Opção informada incorreta !')
        return menuindex()

def mapping():
    pass

def macping(ping_host):
    print("#" * 60)
    os.system(f'ping -c 6 {ping_host}')

def winping(ping_host):
    print("#" * 60)
    os.system(f'ping -n 6 {ping_host}') #sistema Win
