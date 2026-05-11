from sample.mapping import main as mapping
from sample.MainClass import MainClass


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
    while True:
        print('''
 Selecione uma opção :
        1)  Criptografia (Hash)
        2)  Mapeamento de rede IP (Network Mapper)
        3)  Gerar Wordlist (Força Bruta)
        4)  Web Scraping (extração de dados)
        5)  Web Crawler (frequência de palavras)
        6)  Rastreio de Telefone
        7)  Verificar IP externo da rede atual
        8)  WHOIS / DNS Lookup
        9)  Verificador de Headers HTTP
        10) Verificador de Certificado SSL
        11) Encode / Decode (Base64, URL, Hex)
        12) Sair do programa''')
        try:
            index = int(input())
        except ValueError:
            print("Digite um número válido.")
            continue
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
            MainClass.start(url)
        elif index == 6:
            MainClass.phonenum()
        elif index == 7:
            MainClass.ipexterno()
        elif index == 8:
            MainClass.whois_dns_lookup()
        elif index == 9:
            MainClass.check_http_headers()
        elif index == 10:
            MainClass.check_ssl_cert()
        elif index == 11:
            MainClass.encode_decode()
        elif index == 12:
            print("Muito Obrigado por utilizar o Skull Flash !")
            break
        else:
            print("Numero digitado não encontrado")
