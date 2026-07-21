<#
.SYNOPSIS
    Encrypts or decrypts files using B4XCipher-compatible AES-128-CBC encryption.

.DESCRIPTION
    Implements the same encryption algorithm as the B4XEncryption library used in B4A/B4J/B4i.
    Compatível com arquivos encriptados pelo app Android "B4A File Encryptor".
    Algoritmo: AES-128-CBC com PKCS7 padding, PBKDF2-HMACSHA1 (1024 iterações).
    Formato: Salt(8B) || IV(16B) || Ciphertext.

.PARAMETER Path
    Caminho do arquivo ou diretório a processar.

.PARAMETER OutputDir
    Diretório de saída (opcional). Se omitido, usa o mesmo diretório de origem.

.PARAMETER Password
    Senha para encriptação/decriptação. Se omitida, usa a senha padrão do projeto.

.PARAMETER Mode
    Modo de operação: Encrypt (padrão) ou Decrypt.

.PARAMETER Extension
    Extensão de arquivo para filtro no modo diretório (ex: ".sqlite", ".pdf"). Padrão: "*" (todos).

.PARAMETER Recursive
    Se especificado, processa subdiretórios recursivamente no modo diretório.
#>

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Path,

    [Parameter(Position=1)]
    [string]$OutputDir,

    [Parameter()]
    [string]$Password = "mxhaourpollk33078kldjanfap2078anlk903903fanoier",

    [Parameter()]
    [ValidateSet("Encrypt", "Decrypt")]
    [string]$Mode = "Encrypt",

    [Parameter()]
    [string]$Extension = "*",

    [Parameter()]
    [switch]$Recursive
)

# ─────────────────────────────────────────────────────────────
# Funções de encriptação/decriptação (compatível B4XCipher)
# ─────────────────────────────────────────────────────────────

function New-Salt {
    $salt = New-Object byte[] 8
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    $rng.GetBytes($salt)
    return $salt
}

function New-IV {
    $iv = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    $rng.GetBytes($iv)
    return $iv
}



function Derive-Key {
    param([byte[]]$Salt, [string]$Password)
    $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
    $kdf = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($passwordBytes, $Salt, 1024)
    return $kdf.GetBytes(16)
}

function Invoke-AesCbcEncrypt {
    param([byte[]]$Plaintext, [byte[]]$Key, [byte[]]$IV)
    $aes = [System.Security.Cryptography.AesManaged]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.KeySize = 128
    $aes.BlockSize = 128
    $aes.Key = $Key
    $aes.IV = $IV
    $encryptor = $aes.CreateEncryptor()
    $ciphertext = $encryptor.TransformFinalBlock($Plaintext, 0, $Plaintext.Length)
    $aes.Dispose()
    return $ciphertext
}

function Invoke-AesCbcDecrypt {
    param([byte[]]$Ciphertext, [byte[]]$Key, [byte[]]$IV)
    try {
        $aes = [System.Security.Cryptography.AesManaged]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 128
        $aes.BlockSize = 128
        $aes.Key = $Key
        $aes.IV = $IV
        $decryptor = $aes.CreateDecryptor()
        $plaintext = $decryptor.TransformFinalBlock($Ciphertext, 0, $Ciphertext.Length)
        $aes.Dispose()
        return $plaintext
    } catch [System.Security.Cryptography.CryptographicException] {
        Write-Error "Falha na decriptacao. Verifique se a senha (-Password) esta correta."
        Write-Error "Se encriptou com o app Android, use a mesma senha cadastrada nele."
        exit 1
    }
}

function Invoke-B4XEncrypt {
    <#
    Compatível com B4XCipher.java:
    - Salt(8B) + IV(16B) aleatório são gerados e armazenados no output
    - O IV REAL usado na encriptação é o IV armazenado (NÃO zero)
    - Output: Salt(8B) || IV(16B) || AES-128-CBC(PKCS7)
    #>
    param([byte[]]$Data, [string]$Password)
    $salt = New-Salt
    $iv = New-IV
    $key = Derive-Key -Salt $salt -Password $Password
    $ciphertext = Invoke-AesCbcEncrypt -Plaintext $Data -Key $key -IV $iv
    $output = New-Object byte[] (8 + 16 + $ciphertext.Length)
    [System.Array]::Copy($salt, 0, $output, 0, 8)
    [System.Array]::Copy($iv, 0, $output, 8, 16)
    [System.Array]::Copy($ciphertext, 0, $output, 24, $ciphertext.Length)
    return $output
}

function Invoke-B4XDecrypt {
    <#
    Compatível com B4XCipher.java:
    - Extrai Salt(8B) e IV(16B) do input
    - Usa o IV armazenado para decriptação
    #>
    param([byte[]]$Data, [string]$Password)
    if ($Data.Length -lt 24) {
        throw "Arquivo corrompido ou inválido (menos de 24 bytes)."
    }
    $salt = New-Object byte[] 8
    $iv = New-Object byte[] 16
    [System.Array]::Copy($Data, 0, $salt, 0, 8)
    [System.Array]::Copy($Data, 8, $iv, 0, 16)
    $ciphertext = New-Object byte[] ($Data.Length - 24)
    [System.Array]::Copy($Data, 24, $ciphertext, 0, $ciphertext.Length)
    $key = Derive-Key -Salt $salt -Password $Password
    return Invoke-AesCbcDecrypt -Ciphertext $ciphertext -Key $key -IV $iv
}

# ─────────────────────────────────────────────────────────────
# Processamento de arquivos
# ─────────────────────────────────────────────────────────────

function Process-File {
    param([string]$InputFile, [string]$OutDir)

    $fileName = Split-Path $InputFile -Leaf
    $outPath = [System.IO.Path]::Combine($OutDir, $fileName)

    if ($Mode -eq "Encrypt") {
        # Nome completo do arquivo encriptado (incluindo extensão) sempre em minúsculas
        $encFileName = ($fileName + ".en").ToLowerInvariant()
        $outPath = [System.IO.Path]::Combine($OutDir, $encFileName)
        Write-Host "[ENCRIPTANDO] $fileName → $outPath"
        $plainBytes = [System.IO.File]::ReadAllBytes($InputFile)
        $encryptedBytes = Invoke-B4XEncrypt -Data $plainBytes -Password $Password
        [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
    }
    else {
        if (-not $fileName.EndsWith(".en")) {
            Write-Host "[IGNORANDO] $fileName (sem extensão .en)"
            return
        }
        $outPath = $outPath -replace '\.en$', ''
        Write-Host "[DECRIPTANDO] $fileName → $outPath"
        $encryptedBytes = [System.IO.File]::ReadAllBytes($InputFile)
        $plainBytes = Invoke-B4XDecrypt -Data $encryptedBytes -Password $Password
        [System.IO.File]::WriteAllBytes($outPath, $plainBytes)
    }
}

# ─────────────────────────────────────────────────────────────
# Validações iniciais
# ─────────────────────────────────────────────────────────────

$resolvedPath = Resolve-Path $Path -ErrorAction Stop

if (-not (Test-Path $resolvedPath)) {
    Write-Error "Caminho não encontrado: $Path"
    exit 1
}

if (-not $OutputDir) {
    if (Test-Path -Path $resolvedPath -PathType Container) {
        $OutputDir = $resolvedPath
    }
    else {
        $OutputDir = Split-Path $resolvedPath -Parent
    }
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# ─────────────────────────────────────────────────────────────
# Modo diretório vs. arquivo único
# ─────────────────────────────────────────────────────────────

if (Test-Path -Path $resolvedPath -PathType Container) {
    $filter = if ($Extension -eq "*") { "*" } else { "*$Extension" }
    $getParams = @{
        Path    = $resolvedPath
        Filter  = $filter
        File    = $true
    }
    if ($Recursive) { $getParams.Recurse = $true }

    $files = Get-ChildItem @getParams

    if ($files.Count -eq 0) {
        Write-Host "Nenhum arquivo encontrado com extensão '$Extension' em $resolvedPath"
        exit 0
    }

    foreach ($file in $files) {
        Process-File -InputFile $file.FullName -OutDir $OutputDir
    }

    Write-Host "`nProcessados $($files.Count) arquivo(s). Modo: $Mode"
}
else {
    Process-File -InputFile $resolvedPath -OutDir $OutputDir
    Write-Host "`nArquivo processado com sucesso. Modo: $Mode"
}