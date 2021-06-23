import phonenumbers
from phonenumbers import geocoder

def phonenum():
    phone = input("Digite o telefone no formato ex: +551140019999: ")
    phone_num = phonenumbers.parse(phone)
    print(geocoder.description_for_number(phone_num, 'pt'))