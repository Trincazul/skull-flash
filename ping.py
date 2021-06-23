import os
# modificado para funcionar no sistema MacOS
def macping():
    print("#" * 60)
    ping_host = input("Digite o IP ou Host a ser verificado: ")
    os.system('ping -c 6 {}'.format(ping_host))

def winping():
    print("#" * 60)
    ping_host = input("Digite o IP ou Host a ser verificado: ")
    os.system('ping -n 6 {}'.format(ping_host)) #sistema Win
