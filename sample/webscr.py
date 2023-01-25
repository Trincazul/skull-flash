from bs4 import BeautifulSoup
import requests

def webscr(url: str, keyword: str):
    site = requests.get(url).content
    soup = BeautifulSoup(site, 'html.parser')
    print(soup.prettify())
    result = soup.find(keyword)
    if result:
        print(result)
    else:
        print(f"Não foram encontrados resultados para a tag: {keyword}")