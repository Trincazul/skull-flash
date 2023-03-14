import nmap
import os

def mapping():
    print('Mapeamento de IP')
    nm = nmap.PortScanner()
    iptarget = input('Digite o Ip alvo: ')

    nm.scan(f'{iptarget}', '22-40043', timeout=10)
    hosts = nm.all_hosts()
    nm.command_line()
    nm.scaninfo()
    print(hosts)

    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
            
            lport = nm[host][proto].keys()
            lport.sort()
            for port in lport:
                print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

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
        mapping()
    elif option == 2:
        pingmenu()
    else:
        print('Opção errada')
