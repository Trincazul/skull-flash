import re
import json
from urllib.request import urlopen
import webbrowser
from tkinter import *

def ipexterno():
    url = 'http://ipinfo.io/json'

    resposta = urlopen(url)
    dados = json.load(resposta)
    ip = dados['ip']
    org = dados['org']
    cid = dados['city']
    pais = dados['country']
    regiao = dados['region']

    print('Detalhes do IP externo\n')
    print('IP: {4}\nRegião: {1}\nPais: {2}\nCidade: {3}\nOrg: {0}'.format(org,regiao,pais,cid,ip))

    root = Tk()

    root.title('IP Externo da Maquina')
    root.geometry('400x300')

    my = Label(root, text="IP: {4}\nRegião: {1}\nPais: {2}\nCidade: {3}\nOrg: {0}".format(org,regiao,pais,cid,ip)).pack(pady=20)
    root.mainloop()
