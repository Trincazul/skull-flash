import hashlib
import re
import json
from urllib.request import urlopen
import webbrowser
from tkinter import *
from prettytable import PrettyTable
import phonenumbers
from phonenumbers import geocoder
from prettytable import PrettyTable
from bs4 import BeautifulSoup
import requests
import itertools

class MainClass:

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
                            
    #Utilizando a função built-in do python .name para obter o nome da função, dessa forma o usuário sabe o tipo de hash que foi gerado
        if menuhash in hash_options:
            result = hash_options[menuhash](introhash.encode('utf-8'))
            print(f"O {hash_options[menuhash].__name__} hash do texto: {introhash} é: {result.hexdigest()}")
        else:
            print("Selecione uma opção valida")

    def ipexterno():
        url = 'http://ipinfo.io/json'

        resposta = urlopen(url)
        dados = json.load(resposta)
        ip = dados['ip']
        org = dados['org']
        cid = dados['city']
        pais = dados['country']
        regiao = dados['region']
        timezone = dados['timezone']
        tabela = PrettyTable(['IP', 'Região', 'pais', 'Cidade', 'Org', 'Timezone'])
        tabela.add_row([ip,regiao,pais,cid,org,timezone])
        print(tabela)

    def phonenum():
        print("Rastreio de Telefone selecionado ")
        phone = input("Digite o telefone no formato ex: +551140019999: ")
        try:
            phone_num = phonenumbers.parse(phone)
            if phonenumbers.is_valid_number(phone_num):
                tabela = PrettyTable(['Localização', 'Tipo de número', 'País', 'Formato nacional'])
                tabela.add_row([geocoder.description_for_number(phone_num, 'pt'), phonenumbers.number_type(phone_num), phonenumbers.region_code_for_number(phone_num), phonenumbers.format_number(phone_num, phonenumbers.PhoneNumberFormat.NATIONAL)])
                print(tabela)
            else:
                print("Número inválido.")
        except phonenumbers.phonenumberutil.NumberParseException as e:
            print(e)

    def webscr(url: str, keyword: str):
        print("Web Scraping")
        site = requests.get(url).content
        soup = BeautifulSoup(site, 'html.parser')
        print(soup.prettify())
        result = soup.find(keyword)
        if result:
            print(result)
        else:
            print(f"Não foram encontrados resultados para a tag: {keyword}")

    def wordlist():
        string = input("String a ser permutada: ")
        size = int(input("Tamanho da permutação (digite 0 para usar tamanho da string): ")) or len(string)
        repeat = input("Permutações com repetição? (s/n)").lower() == 's'
        save_file = input("Salvar resultado em arquivo? (s/n)").lower() == 's'
        filename = input("Nome do arquivo: ") if save_file else None
        include = input("Incluir caracteres específicos? (s/n)").lower() == 's'
        if include:
            include_list = input("Lista de caracteres (separados por vírgula): ").split(',')
            string += ''.join(include_list)
        exclude = input("Excluir caracteres específicos? (s/n)").lower() == 's'
        if exclude:
            exclude_list = input("Lista de caracteres (separados por vírgula): ").split(',')
            for char in exclude_list:
                string = string.replace(char, '')
        prohibited = input("Excluir palavras proibidas? (s/n)").lower() == 's'
        prohibited_list = input("Lista de palavras (separadas por vírgula): ").split(',') if prohibited else []
        lexicographic = input("Permutações em ordem lexicográfica? (s/n)").lower() == 's'
        
        if lexicographic:
            resultado = itertools.permutations(sorted(string), size) if repeat else itertools.permutations(sorted(string), size)
        else:
            resultado = itertools.product(string, repeat=size) if repeat else itertools.permutations(string, size)

        resultado = [''.join(x) for x in resultado if all(prohibited_word not in ''.join(x) for prohibited_word in prohibited_list)]
        if save_file:
            with open(filename, 'w') as f:
                f.write('\n'.join(resultado))
        else:
            print('\n'.join(resultado))