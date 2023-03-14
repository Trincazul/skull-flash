from sample.mapping import main as mapping
from sample.webcrawler import start

from sample.MainClass import *

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
        2) Mapeamento de rede IP (Network Mapper)
        3) Gerar Wordlist (Força Bruta)
        4) Web Scraping (extração de dados)
        5) Web Crawler
        6) Rastreio de Telefone
        7) Verificar IP externo da rede atual
        8) Sair do programa''')
    index = int(input())
    if index == 1:
        MainClass.hashgen()
    elif index == 2:
        mapping()
    elif index == 3:
        MainClass.wordlist()
    elif index == 4:
        url = input("Selecione o site para fazer varredura, lembre-se de adicionar o http:// : ")
        keyword = input("Palavra chave ('tag') da varredura: ")
        MainClass.webscr(url, keyword)
    elif index == 5:
        print("Adicione o site para ler e indexar as paginas lembre-se de utilizar sites com http:// : ")
        url = input()
        start(url)
    elif index == 6:
        MainClass.phonenum()
    elif index == 7:
        MainClass.ipexterno()
    elif index == 8:
        print("Muito Obrigado por utilizar o Skull Flash !")
    else:
        print("Numero digitado não encontrado")

    while index != 8:
        return menuindex()
