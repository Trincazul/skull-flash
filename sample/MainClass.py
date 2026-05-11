import hashlib
import json
import ssl
import socket
import base64
from urllib.request import urlopen
from urllib.parse import quote, unquote
from prettytable import PrettyTable
import phonenumbers
from phonenumbers import geocoder
from bs4 import BeautifulSoup
import requests
import itertools
import operator
from collections import Counter


class MainClass:

    @staticmethod
    def hashgen():
        introhash = input("Digite o texto a ser gerado a Hash: ")

        hash_options = {
            1: hashlib.md5,
            2: hashlib.sha1,
            3: hashlib.sha256,
            4: hashlib.sha512
        }

        try:
            menuhash = int(input('''Menu de Criptografia, Hash
                            1) - MD5
                            2) - SHA1
                            3) - SHA256
                            4) - SHA512
                            Digite o numero do hash a ser gerado: '''))
        except ValueError:
            print("Selecione uma opção valida")
            return

        if menuhash in hash_options:
            result = hash_options[menuhash](introhash.encode('utf-8'))
            print(f"O {hash_options[menuhash].__name__} hash do texto: {introhash} é: {result.hexdigest()}")
        else:
            print("Selecione uma opção valida")

    @staticmethod
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
        tabela = PrettyTable(['IP', 'Região', 'País', 'Cidade', 'Org', 'Timezone'])
        tabela.add_row([ip, regiao, pais, cid, org, timezone])
        print(tabela)

    @staticmethod
    def phonenum():
        print("Rastreio de Telefone selecionado ")
        phone = input("Digite o telefone no formato ex: +551140019999: ")
        try:
            phone_num = phonenumbers.parse(phone)
            if phonenumbers.is_valid_number(phone_num):
                tabela = PrettyTable(['Localização', 'Tipo de número', 'País', 'Formato nacional'])
                tabela.add_row([
                    geocoder.description_for_number(phone_num, 'pt'),
                    phonenumbers.number_type(phone_num),
                    phonenumbers.region_code_for_number(phone_num),
                    phonenumbers.format_number(phone_num, phonenumbers.PhoneNumberFormat.NATIONAL)
                ])
                print(tabela)
            else:
                print("Número inválido.")
        except phonenumbers.phonenumberutil.NumberParseException as e:
            print(e)

    @staticmethod
    def webscr(url: str, keyword: str):
        print("Web Scraping")
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            print(soup.prettify())
            result = soup.find(keyword)
            if result:
                print(result)
            else:
                print(f"Não foram encontrados resultados para a tag: {keyword}")
        except requests.RequestException as e:
            print(f"Erro ao acessar URL: {e}")

    @staticmethod
    def wordlist():
        string = input("String a ser permutada: ")
        try:
            size = int(input("Tamanho da permutação (digite 0 para usar tamanho da string): ")) or len(string)
        except ValueError:
            print("Tamanho inválido. Usando tamanho da string.")
            size = len(string)
        repeat = input("Permutações com repetição? (s/n) ").lower() == 's'
        save_file = input("Salvar resultado em arquivo? (s/n) ").lower() == 's'
        filename = input("Nome do arquivo: ") if save_file else None
        include = input("Incluir caracteres específicos? (s/n) ").lower() == 's'
        if include:
            include_list = input("Lista de caracteres (separados por vírgula): ").split(',')
            string += ''.join(include_list)
        exclude = input("Excluir caracteres específicos? (s/n) ").lower() == 's'
        if exclude:
            exclude_list = input("Lista de caracteres (separados por vírgula): ").split(',')
            for char in exclude_list:
                string = string.replace(char, '')
        prohibited = input("Excluir palavras proibidas? (s/n) ").lower() == 's'
        prohibited_list = input("Lista de palavras (separadas por vírgula): ").split(',') if prohibited else []
        lexicographic = input("Permutações em ordem lexicográfica? (s/n) ").lower() == 's'

        source = sorted(string) if lexicographic else list(string)
        if repeat:
            resultado = itertools.product(source, repeat=size)
        else:
            resultado = itertools.permutations(source, size)

        resultado = [
            ''.join(x) for x in resultado
            if all(p not in ''.join(x) for p in prohibited_list)
        ]
        if save_file:
            with open(filename, 'w') as f:
                f.write('\n'.join(resultado))
        else:
            print('\n'.join(resultado))

    @staticmethod
    def start(url):
        wordlist = []
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Erro ao acessar URL: {e}")
            return
        soup = BeautifulSoup(response.text, 'html.parser')
        for each_text in soup.findAll('div', {'class': 'entry-content'}):
            content = each_text.text
            for each_word in content.lower().split():
                wordlist.append(each_word)
        MainClass.clean_wordlist(wordlist)

    @staticmethod
    def clean_wordlist(wordlist):
        clean_list = []
        symbols = '!@#$%¨*()_+={}[]><;^/|., '
        for word in wordlist:
            for symbol in symbols:
                word = word.replace(symbol, '')
            if word:
                clean_list.append(word)
        MainClass.create_dictionary(clean_list)

    @staticmethod
    def create_dictionary(clean_list):
        word_count = Counter(clean_list)
        for key, value in sorted(word_count.items(), key=operator.itemgetter(1)):
            print(f"{key} : {value}")
        print(word_count.most_common(10))

    @staticmethod
    def whois_dns_lookup():
        print('''
    1) WHOIS  (registro de domínio)
    2) DNS Lookup (registros A, MX, NS, TXT)''')
        try:
            option = int(input("Selecione: "))
        except ValueError:
            print("Opção inválida.")
            return

        domain = input("Digite o domínio (ex: google.com): ").strip()

        if option == 1:
            try:
                import whois
                w = whois.whois(domain)

                def fmt(val):
                    if isinstance(val, list):
                        return ', '.join(str(v) for v in val[:3])
                    return str(val) if val else 'N/A'

                tabela = PrettyTable(['Campo', 'Valor'])
                tabela.max_width = 60
                tabela.add_row(['Domínio',     fmt(w.domain_name)])
                tabela.add_row(['Registrador', fmt(w.registrar)])
                tabela.add_row(['Criado em',   fmt(w.creation_date)])
                tabela.add_row(['Expira em',   fmt(w.expiration_date)])
                tabela.add_row(['Servidores NS', fmt(w.name_servers)])
                print(tabela)
            except ImportError:
                print("Instale a dependência: pip install python-whois")
            except Exception as e:
                print(f"Erro na consulta WHOIS: {e}")

        elif option == 2:
            try:
                import dns.resolver
                for rtype in ['A', 'MX', 'NS', 'TXT']:
                    try:
                        answers = dns.resolver.resolve(domain, rtype)
                        tabela = PrettyTable(['Tipo', 'Valor'])
                        tabela.max_width = 70
                        for rdata in answers:
                            tabela.add_row([rtype, rdata.to_text()])
                        print(tabela)
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        print(f"Sem registros {rtype} para {domain}")
            except ImportError:
                print("Instale a dependência: pip install dnspython")
            except Exception as e:
                print(f"Erro DNS: {e}")
        else:
            print("Opção inválida.")

    @staticmethod
    def check_http_headers():
        url = input("Digite a URL (ex: https://google.com): ").strip()
        security_headers = [
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Content-Security-Policy',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy',
        ]
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            tabela = PrettyTable(['Header de Segurança', 'Status', 'Valor'])
            tabela.max_width = 50
            for header in security_headers:
                if header in response.headers:
                    tabela.add_row([header, 'Presente', response.headers[header][:50]])
                else:
                    tabela.add_row([header, 'AUSENTE', '-'])
            print(tabela)
        except requests.RequestException as e:
            print(f"Erro ao acessar URL: {e}")

    @staticmethod
    def check_ssl_cert():
        domain = input("Digite o domínio (sem https://, ex: google.com): ").strip()
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(10)
                s.connect((domain, 443))
                cert = s.getpeercert()

            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
            san = [v for _, v in cert.get('subjectAltName', [])]

            tabela = PrettyTable(['Campo', 'Valor'])
            tabela.max_width = 60
            tabela.add_row(['Domínio (CN)',  subject.get('commonName', 'N/A')])
            tabela.add_row(['Organização',   subject.get('organizationName', 'N/A')])
            tabela.add_row(['Emissor',       issuer.get('organizationName', 'N/A')])
            tabela.add_row(['Válido de',     cert['notBefore']])
            tabela.add_row(['Válido até',    cert['notAfter']])
            tabela.add_row(['SANs',          ', '.join(san[:5])])
            print(tabela)
        except ssl.SSLCertVerificationError as e:
            print(f"Certificado inválido: {e}")
        except ssl.SSLError as e:
            print(f"Erro SSL: {e}")
        except (socket.gaierror, socket.timeout) as e:
            print(f"Erro de conexão: {e}")

    @staticmethod
    def encode_decode():
        print('''
    1) Codificar   Base64
    2) Decodificar Base64
    3) Codificar   URL
    4) Decodificar URL
    5) Codificar   Hexadecimal
    6) Decodificar Hexadecimal''')
        try:
            option = int(input("Selecione: "))
        except ValueError:
            print("Opção inválida.")
            return

        text = input("Digite o texto: ")

        try:
            if option == 1:
                result = base64.b64encode(text.encode()).decode()
            elif option == 2:
                result = base64.b64decode(text).decode()
            elif option == 3:
                result = quote(text)
            elif option == 4:
                result = unquote(text)
            elif option == 5:
                result = text.encode().hex()
            elif option == 6:
                result = bytes.fromhex(text).decode()
            else:
                print("Opção inválida.")
                return
        except Exception as e:
            print(f"Erro ao processar: {e}")
            return

        print(f"\nResultado: {result}")
