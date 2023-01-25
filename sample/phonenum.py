import phonenumbers
from phonenumbers import geocoder

def phonenum():
    phone = input("Digite o telefone no formato ex: +551140019999: ")
    try:
        phone_num = phonenumbers.parse(phone)
        if phonenumbers.is_valid_number(phone_num):
            print(geocoder.description_for_number(phone_num, 'pt'))
            print(f"Tipo de número:{phonenumbers.number_type(phone_num)}")
            print(f"País: {phonenumbers.region_code_for_number(phone_num)}")
            print(f"Formato nacional: {phonenumbers.format_number(phone_num, phonenumbers.PhoneNumberFormat.NATIONAL)}")
        else:
            print("Número inválido.")
    except phonenumbers.phonenumberutil.NumberParseException as e:
        print(e)