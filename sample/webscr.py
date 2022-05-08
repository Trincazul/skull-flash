from bs4 import BeautifulSoup
import requests

def webscr():
    alvo = input("Selecione o site para fazer varredura, lembre-se de adicionar o http:// : ")
    site = requests.get(alvo).content
    #objeto recebendo o conteudo da requisição http do site

    soup = BeautifulSoup(site, 'html.parser')
    print(soup.prettify())
    findsoup = input("Palavra chave ('tag') da varredura: ")

    print(soup.find(findsoup))


