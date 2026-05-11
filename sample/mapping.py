import nmap
import subprocess
from prettytable import PrettyTable


def mapping(iptarget, portini, portfin):
    print('Fazendo o mapeamento na rede - Aguarde')
    nm = nmap.PortScanner()
    nm.scan(iptarget, f'{portini}-{portfin}')

    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print(f'Host : {host} ({nm[host].hostname()})')
        print(f'State : {nm[host].state()}')
        tabela = PrettyTable(['Porta', 'Estado', 'Nome', 'Versão', 'Descrição'])
        for proto in nm[host].all_protocols():
            print('----------')
            print(f'Protocol : {proto}')
            lport = sorted(nm[host][proto].keys())
            for port in lport:
                tabela.add_row([
                    port,
                    nm[host][proto][port]['state'],
                    nm[host][proto][port]['name'],
                    nm[host][proto][port]['version'],
                    nm[host][proto][port]['product']
                ])
            print(tabela)


def pingmenu():
    print('''Selecione o sistema operacional
                1) - Mac ou Linux
                2) - Windows''')
    try:
        sisop = int(input())
    except ValueError:
        print('Opção informada incorreta !')
        return
    ping_host = input("Digite o IP ou Host a ser verificado: ")
    if sisop == 1:
        print("#" * 60)
        subprocess.run(['ping', '-c', '6', ping_host])
    elif sisop == 2:
        print("#" * 60)
        subprocess.run(['ping', '-n', '6', ping_host])
    else:
        print('Opção informada incorreta !')


def main():
    try:
        option = int(input('''Selecione -> 1 para mapeamento de rede:
Selecione -> 2 para fazer um ping simples no IP:  '''))
    except ValueError:
        print('Opção errada')
        return

    if option == 1:
        iptarget = input('Digite o Ip alvo: ')
        portini = input('Porta de inicio para varredura: ')
        portfin = input('Porta para final de varredura: ')
        if not (portini.isdigit() and portfin.isdigit()):
            print('Portas inválidas. Informe números inteiros.')
            return
        if not (1 <= int(portini) <= 65535 and 1 <= int(portfin) <= 65535):
            print('Portas devem estar entre 1 e 65535.')
            return
        mapping(iptarget, portini, portfin)
    elif option == 2:
        pingmenu()
    else:
        print('Opção errada')


if __name__ == '__main__':
    main()
