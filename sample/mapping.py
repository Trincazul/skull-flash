import nmap
import os
from prettytable import PrettyTable


def mapping(iptarget):
    print('Fazendo o mapeamento na rede - Aguarde')
    nm = nmap.PortScanner()
    
    scan = nm.scan(iptarget, '22-10000')
    hosts = nm.all_hosts()
    nm.command_line()
    nm.scaninfo()

    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print(f'Host : {host} ({nm[host].hostname()})')
        print(f'State : {nm[host].state()}')
        tabela = PrettyTable(['Porta', 'Estado', 'Nome', 'Versão', 'Descrição'])
        for proto in nm[host].all_protocols():
            print('----------')
            print(f'Protocol : {proto}')
            
            lport = list(nm[host][proto].keys())
            lport.sort()
            for port in lport:
                tabela.add_row([port, nm[host][proto][port]['state'], nm[host][proto][port]['name'], nm[host][proto][port]['version'], nm[host][proto][port]['product']])            
            print(tabela)
            #tabela.csv()

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
        iptarget = input('Digite o Ip alvo: ')
        mapping(iptarget)
    elif option == 2:
        pingmenu()
    else:
        print('Opção errada')

if __name__ == '__main__':
    main()
