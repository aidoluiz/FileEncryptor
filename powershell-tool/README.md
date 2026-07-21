# B4A File Encryptor — PowerShell Tool

Script PowerShell para encriptar/decriptar arquivos usando o mesmo algoritmo
do app Android **B4A File Encryptor** (compatível com `B4XCipher`).

## Algoritmo

| Parâmetro | Valor |
|---|---|
| Cifra | AES-128-CBC |
| Padding | PKCS7 |
| Derivação de chave | PBKDF2-HMACSHA1, 1024 iterações |
| Salt | 8 bytes aleatórios |
| IV | 16 bytes aleatórios |
| Tamanho da chave | 128 bits |
| Encoding do password | UTF-8 |
| Formato do arquivo | `Salt(8B) \| IV(16B) \| Ciphertext` |
| Extensão encriptado | `.en` (adicionado ao final do nome) |

Totalmente compatível com os arquivos gerados pelo app B4A original e pela
biblioteca B4XEncryption (B4J/B4i).

## Pré-requisitos

- Windows PowerShell 5.1 ou superior
- Nenhuma biblioteca externa necessária (usa `System.Security.Cryptography` nativo do .NET)

## Parâmetros

| Parâmetro | Obrigatório | Posição | Descrição |
|---|---|---|---|
| `-Path` | Sim | 0 | Caminho do arquivo ou diretório a processar |
| `-OutputDir` | Não | 1 | Diretório de saída (padrão: mesmo diretório de origem) |
| `-Password` | Não | — | Senha (padrão: mesma do projeto B4A) |
| `-Mode` | Não | — | `Encrypt` (padrão) ou `Decrypt` |
| `-Extension` | Não | — | Filtro de extensão no modo diretório (ex: `.sqlite`, `.pdf`). Padrão: `*` (todos) |
| `-Recursive` | Não | — | Se especificado, processa subdiretórios recursivamente |

## Modos de uso

### 1. Encriptar um arquivo único

```powershell
.\B4AFileEncryptor.ps1 "C:\dados\meu_arquivo.sqlite"
```

### 2. Encriptar com senha personalizada e diretório de saída

```powershell
.\B4AFileEncryptor.ps1 "C:\dados\arquivo.pdf" "C:\encriptados" -Password "minha_senha"
```
########## VESAO .BAT QUE FUNCIONOU SEM PERMISSAO ############
	'INFRANOTE PRO E FICHAS DO INFRANOTE
	FilePassword = "mxhaourpollk33078kldjanfap2078anlk903903fanoier"

	'INFRANOTE Database compra de pacotes  ????
	'FilePassword = "kzgadaep19309141ladmafadfpkjdlsjaf13641kadfjkaafmzz01329084901300143fdaalfj32piioduf0aahfa90dflafkadmf"	
	
	'INFRANOTE controle.sqlite
	'FilePassword = "xhrytiwa873z980kllki7801"

Digitar o comando dentro da pasta powershell-tool. Vai salvar o arquivo encriptado na pasta do arquivo original.

cd .\powershell-tool\

INFRANOTE PRO E FICHAS DO INFRANOTE
.\B4AFileEncryptor.cmd ..\Files\resolucoesv3.sqlite -Password "mxhaourpollk33078kldjanfap2078anlk903903fanoier"

INFRANOTE controle.sqlite
.\B4AFileEncryptor.cmd ..\Files\controle.sqlite -Password "xhrytiwa873z980kllki7801"


### 3. Decriptar um arquivo `.en`

```powershell
.\B4AFileEncryptor.ps1 "C:\encriptados\arquivo.sqlite.en" -Mode Decrypt
```

### 4. Encriptar todos os arquivos de um diretório

```powershell
.\B4AFileEncryptor.ps1 "C:\dados" -OutputDir "C:\encriptados"
```

### 5. Encriptar apenas arquivos `.sqlite` de um diretório

```powershell
.\B4AFileEncryptor.ps1 "C:\dados" -OutputDir "C:\encriptados" -Extension ".sqlite"
```

### 6. Decriptar todos os `.en` de um diretório recursivamente

```powershell
.\B4AFileEncryptor.ps1 "C:\encriptados" -Mode Decrypt -Recursive
```

### 7. Usar as senhas alternativas do projeto original

```powershell
# Database de compra de pacotes
.\B4AFileEncryptor.ps1 "C:\dados\pacotes.sqlite" -Password "kzgadaep19309141ladmafadfpkjdlsjaf13641kadfjkaafmzz01329084901300143fdaalfj32piioduf0aahfa90dflafkadmf"

# controle.sqlite
.\B4AFileEncryptor.ps1 "C:\dados\controle.sqlite" -Password "xhrytiwa873z980kllki7801"
```

## Observações

- Arquivos encriptados recebem a extensão `.en` no final do nome original.
- Na decriptação, a extensão `.en` é removida automaticamente.
- Arquivos sem `.en` são ignorados no modo `Decrypt`.
- O script é compatível com arquivos encriptados pelo app Android original
  e vice-versa (pode decriptar com o app Android arquivos gerados por este script).

## Estrutura de arquivos

```
powershell-tool\
├── B4AFileEncryptor.ps1   # Script principal
└── README.md              # Esta documentação
```