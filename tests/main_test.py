#!/usr/bin/python3

import json
import subprocess
from urllib.request import urlopen
from unittest import main, TestCase


class TestMainFunctions(TestCase):
    def test_ip_api_returns_data(self):
        url = 'http://ipinfo.io/json'
        resposta = urlopen(url)
        dados = json.load(resposta)
        self.assertTrue(dados)

    def test_ip_api_returns_region(self):
        url = 'http://ipinfo.io/json'
        resposta = urlopen(url)
        dados = json.load(resposta)
        regiao = dados['region']
        self.assertIsNotNone(regiao)
        self.assertNotEqual(regiao, '')

    def test_ping_localhost(self):
        result = subprocess.run(
            ['ping', '-n', '1', '127.0.0.1'],
            capture_output=True
        )
        self.assertEqual(result.returncode, 0)


if __name__ == '__main__':
    main()
