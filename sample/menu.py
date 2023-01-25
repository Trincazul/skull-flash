from sample.hash_generator import hashgen
from sample.ping import macping, winping
from sample.wordlist import wordlist
from sample.webscr import webscr
from sample.webcrawler import start
from sample.phonenum import phonenum
from sample.ipexter import ipexterno
from sample.opbx import opbx

def image():
    print('''
███████████████████████████
███████▀▀▀░░░░░░░▀▀▀███████
████▀░░░░░░░░░░░░░░░░░▀████
███│░░░░░░░░░░░░░░░░░░░│███
██▌│░░░░░░░░░░░░░░░░░░░│▐██
██░└┐░░░░░░░░░░░░░░░░░┌┘░██
██░░└┐░░░░░░░░░░░░░░░┌┘░░██
██░░┌┘▄▄▄▄▄░░░░░▄▄▄▄▄└┐░░██
██▌░│██████▌░░░▐██████│░▐██
███░│▐███▀▀░░▄░░▀▀███▌│░███
██▀─┘░░░░░░░▐█▌░░░░░░░└─▀██
██▄░░░▄▄▄▓░░▀█▀░░▓▄▄▄░░░▄██
████▄─┘██▌░░░░░░░▐██└─▄████
█████░░▐█─┬┬┬┬┬┬┬─█▌░░█████
████▌░░░▀┬┼┼┼┼┼┼┼┬▀░░░▐████
█████▄░░░└┴┴┴┴┴┴┴┘░░░▄█████
███████▄░░░░░░░░░░░▄███████
██████████▄▄▄▄▄▄▄██████████
███████████████████████████
  / ____| | |            | | | |
 | (___   | | __  _   _  | | | |
  \___ \  | |/ / | | | | | | | |
  ____) | |   <  | |_| | | | | |
 |_____/  |_|\_\  \__,_| |_| |_|
  ______   _                 _
 |  ____| | |               | |
 | |__    | |   __ _   ___  | |__
 |  __|   | |  / _` | / __| | '_ |
 | |      | | | (_| | \__ \ | | | |
 |_|      |_|  \__,_| |___/ |_| |_|
''')

def menuindex():
    print('''
 Selecione uma opção :
        1) Criptografia
        2) Ping
        3) Gerar Wordlist (Força Bruta)
        4) Web Scraping (extração de dados)
        5) Web Crawler
        6) Rastreio de Telefone
        7) Verificar IP externo
        8) Abrir Navegador
        9) Sair do programa''')
    index = int(input())
    if index == 1:
        hashgen()
    elif index == 2:
        print('''Selecione o sistema operacional
                 1) - Mac ou Linux
                 2) - Windows''')
        sisop = int(input())
        if sisop == 1:
            macping()
        elif sisop == 2:
            winping()
        else:
            print('Opção informada incorreta !')
            return menuindex()

    elif index == 3:
        print("Wordlist")
        wordlist()
    elif index == 4:
        print("Web Scraping")
        url = input("Selecione o site para fazer varredura, lembre-se de adicionar o http:// : ")
        keyword = input("Palavra chave ('tag') da varredura: ")
        webscr(url, keyword)
    elif index == 5:
        print("Adicione o site para ler e indexar as paginas lembre-se de utilizar sites com http:// : ")
        url = input()
        start(url)
    elif index == 6:
        print("Rastreio")
        phonenum()
    elif index == 7:
        ipexterno()
    elif index == 8:
        opbx()
    elif index == 9:
        print("Muito Obrigado por utilizar o Skull Flash !")
    else:
        print("Numero digitado não encontrado")

    while index != 9:
        return menuindex()
