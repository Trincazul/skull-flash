import ctypes

arq = input("Adicione o nome do arquivo a ser ocultado: ")
atr_ocult = 0x02
retr = ctypes.windll.karnel32.SetFileAttributesW('ocultar.txt', atr_ocult)

if retr:
    print("Arquivo foi ocultado")
else:
    print("Arquivo não foi ocultado")