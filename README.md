# Basic login Proxy

Proxy para fazer login em contas usando UID e password.

## Funcionalidades

- Intercepta requisições TokenGrant e substitui automaticamente o UID e password
- Atualiza automaticamente os dados quando o `login.json` é modificado
- Suporta descriptografia AES-CBC quando necessário

## Requisitos

- Python 3.x
- Dependências do `requirements.txt`

## Instalação

```bash
pip install -r requirements.txt
```

## Configuração

Edite o arquivo `login.json` com seus dados:

```json
[
    {
        "uid": "4259184835",
        "password": "4C6887FCC83BF8D2035BB694E99563D548E13A7D3AA44C07AA49C417685B4687",
        "account_id": 13725897453,
        "name": "POTENTE⁹⁸³⁸",
        "region": "BR"
    }
]
```

## Uso

Execute o proxy na porta 8080:

```bash
mitmdump -s proxy.py -p 8080
```

Configure o dispositivo/aplicativo para usar o proxy na porta 8080.

O script irá interceptar as requisições TokenGrant e usar automaticamente o UID e password do `login.json`.

## Atualização de Dados

Você pode modificar o `login.json` enquanto o proxy está rodando. Os novos dados serão carregados automaticamente na próxima requisição interceptada.

## Arquivos Necessários

- `proxy.py` - Script principal
- `AES.py` - Utilitário de criptografia
- `login.json` - Dados de login (crie este arquivo)

## Créditos

By: liox  
Discord: assumiu
server: https://discord.gg/d2PP9rYbeY
