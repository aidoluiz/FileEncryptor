<#
.SYNOPSIS
    Versao interativa do B4XFileEncryptor + PDFtoBLOB com gerenciamento de senhas.
#>

Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop | Out-Null

# ── Plataforma atual ──

$script:CurrentPlatform = "Android"  # "Android" ou "iOS"

# ── Crypto ──

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
    $aes.KeySize = 128; $aes.BlockSize = 128
    $aes.Key = $Key; $aes.IV = $IV
    $encryptor = $aes.CreateEncryptor()
    $ciphertext = $encryptor.TransformFinalBlock($Plaintext, 0, $Plaintext.Length)
    $aes.Dispose()
    return $ciphertext
}

function Invoke-AesCbcDecrypt {
    param([byte[]]$Ciphertext, [byte[]]$Key, [byte[]]$IV)
    $aes = [System.Security.Cryptography.AesManaged]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.KeySize = 128; $aes.BlockSize = 128
    $aes.Key = $Key; $aes.IV = $IV
    $decryptor = $aes.CreateDecryptor()
    $plaintext = $decryptor.TransformFinalBlock($Ciphertext, 0, $Ciphertext.Length)
    $aes.Dispose()
    return $plaintext
}

function Invoke-B4XEncrypt {
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
    param([byte[]]$Data, [string]$Password)
    if ($Data.Length -lt 24) { throw "Arquivo corrompido (menos de 24 bytes)." }
    $salt = New-Object byte[] 8
    $iv = New-Object byte[] 16
    [System.Array]::Copy($Data, 0, $salt, 0, 8)
    [System.Array]::Copy($Data, 8, $iv, 0, 16)
    $ciphertext = New-Object byte[] ($Data.Length - 24)
    [System.Array]::Copy($Data, 24, $ciphertext, 0, $ciphertext.Length)
    $key = Derive-Key -Salt $salt -Password $Password
    return Invoke-AesCbcDecrypt -Ciphertext $ciphertext -Key $key -IV $iv
}

# ── Gerenciamento de senhas ──

$ANDROID_DEFAULT_PASSWORD = "mxhaourpollk33078kldjanfap2078anlk903903fanoier"
$IOS_DEFAULT_PASSWORD     = "o3u42llqj54120kljflaldj"

function Get-PlatformDefaultPassword {
    if ($script:CurrentPlatform -eq "iOS") { return $IOS_DEFAULT_PASSWORD }
    return $ANDROID_DEFAULT_PASSWORD
}

function Get-PlatformDefaultName {
    if ($script:CurrentPlatform -eq "iOS") { return "iOS (padrao)" }
    return "Android (padrao)"
}

function Get-PasswordFilePath {
    $scriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path $MyInvocation.MyCommand.Path -Parent } else { (Get-Location).Path }
    $suffix = if ($script:CurrentPlatform -eq "iOS") { "_ios" } else { "_android" }
    return Join-Path $scriptDir "passwords$suffix.json"
}

function Load-PasswordList {
    $path = Get-PasswordFilePath
    if (Test-Path $path) {
        try {
            $json = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
            $list = @($json.entries)
            $defIdx = [int]$json.defaultIndex
            return @{ List = $list; DefaultIndex = $defIdx }
        } catch {
            return @{ List = @(); DefaultIndex = -1 }
        }
    }
    return @{ List = @(); DefaultIndex = -1 }
}

function Save-PasswordList {
    param([array]$List, [int]$DefaultIndex)
    $path = Get-PasswordFilePath
    $obj = @{ defaultIndex = $DefaultIndex; entries = @($List) }
    $obj | ConvertTo-Json -Compress | Set-Content $path -Encoding UTF8
}

function Get-DefaultPassword {
    $data = Load-PasswordList
    if ($data.DefaultIndex -ge 0 -and $data.DefaultIndex -lt $data.List.Count) {
        $entry = $data.List[$data.DefaultIndex]
        if ($entry.Password) { return $entry.Password }
    }
    return Get-PlatformDefaultPassword
}

function Get-DefaultPasswordName {
    $data = Load-PasswordList
    if ($data.DefaultIndex -ge 0 -and $data.DefaultIndex -lt $data.List.Count) {
        $entry = $data.List[$data.DefaultIndex]
        if ($entry.Name) { return $entry.Name }
    }
    return Get-PlatformDefaultName
}

# ── UI ──

function Write-Header {
    Clear-Host
    $platformColor = if ($script:CurrentPlatform -eq "iOS") { "Magenta" } else { "Green" }
    $platformLine = if ($script:CurrentPlatform -eq "iOS") {
        "|   Encriptacao/Decriptacao compativel com iOS (B4i)        |"
    } else {
        "|   Encriptacao/Decriptacao compativel com Android (B4A)    |"
    }
    Write-Host "+========================================================+" -ForegroundColor Cyan
    Write-Host "|      B4X FILE ENCRYPTOR + PDFtoBLOB - v1.0            |" -ForegroundColor Yellow
    Write-Host "|   Encrypt/Decrypt/PDFtoBLOB compatível B4A/B4i        |" -ForegroundColor White
    Write-Host "$platformLine" -ForegroundColor $platformColor
    Write-Host "+========================================================+" -ForegroundColor Cyan
    Write-Host "  Plataforma: " -NoNewline; Write-Host $script:CurrentPlatform -ForegroundColor $platformColor
    Write-Host ""
}

function Write-Success { param([string]$Msg); Write-Host "  [+] " -ForegroundColor Green -NoNewline; Write-Host $Msg }
function Write-Error   { param([string]$Msg); Write-Host "  [!] " -ForegroundColor Red -NoNewline; Write-Host $Msg }
function Write-Info    { param([string]$Msg); Write-Host "  -> " -ForegroundColor Yellow -NoNewline; Write-Host $Msg }

function Show-Menu {
    param([string]$Title, [array]$Options)
    Write-Host "  $Title" -ForegroundColor White
    Write-Host ""
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host "     $($Options[$i])" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "  Use setas (cima/baixo), letras ou Enter" -ForegroundColor DarkGray
    
    $selected = 0
    $menuTop = [Console]::CursorTop - ($Options.Count + 4)
    
    do {
        for ($i = 0; $i -lt $Options.Count; $i++) {
            $row = $menuTop + 2 + $i
            [Console]::SetCursorPosition(4, $row)
            if ($i -eq $selected) {
                Write-Host ">>" -NoNewline -ForegroundColor Cyan
                Write-Host " $($Options[$i])" -ForegroundColor Cyan
            } else {
                Write-Host "  " -NoNewline -ForegroundColor DarkGray
                Write-Host " $($Options[$i])" -ForegroundColor DarkGray
            }
        }
        [Console]::SetCursorPosition(0, $menuTop + $Options.Count + 4)
        
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        if ($key.VirtualKeyCode -eq 38 -and $selected -gt 0) { $selected-- }
        elseif ($key.VirtualKeyCode -eq 40 -and $selected -lt $Options.Count - 1) { $selected++ }
        elseif ($key.VirtualKeyCode -eq 13) { break }
        elseif ($key.Character -ne 0) {
            $char = $key.Character.ToString().ToLower()
            for ($i = 0; $i -lt $Options.Count; $i++) {
                $optChar = if ($Options[$i] -match '^\[(\w)\]') { $Matches[1].ToLower() } else { $null }
                if ($optChar -eq $char) { $selected = $i; break }
            }
            if ($i -lt $Options.Count) { break }
        }
        
    } while ($true)
    
    [Console]::SetCursorPosition(0, $menuTop + $Options.Count + 4)
    Write-Host "                                        " -NoNewline
    [Console]::SetCursorPosition(0, $menuTop + $Options.Count + 4)
    
    return $selected
}

# ── Seletores Windows ──

function Select-Files {
    param([string]$Title, [string]$Filter, [string]$InitialDir)
    $d = New-Object System.Windows.Forms.OpenFileDialog
    $d.Title = $Title; $d.Multiselect = $true; $d.CheckFileExists = $true
    $d.InitialDirectory = $InitialDir
    if ($Filter) { $d.Filter = $Filter }
    if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $d.FileNames }
    return $null
}

function Select-Folder {
    param([string]$Desc, [string]$InitialDir)
    $d = New-Object System.Windows.Forms.FolderBrowserDialog
    $d.Description = $Desc; $d.SelectedPath = $InitialDir; $d.ShowNewFolderButton = $true
    if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $d.SelectedPath }
    return $null
}

# ── Gerenciador de senhas ──

function Show-PasswordManager {
    Write-Header
    Write-Host "  GERENCIADOR DE SENHAS [$($script:CurrentPlatform)]" -ForegroundColor White
    Write-Host ""
    
    $data = Load-PasswordList
    $list = $data.List
    $defIdx = $data.DefaultIndex
    
    do {
        Write-Header
        Write-Host "  GERENCIADOR DE SENHAS [$($script:CurrentPlatform)]" -ForegroundColor White
        Write-Host ""
        
        if ($list.Count -eq 0) {
            Write-Host "  Nenhuma senha cadastrada." -ForegroundColor DarkGray
            Write-Host ""
            $action = Show-Menu -Title "" -Options @("[A] Adicionar nova senha", "[V] Voltar ao menu principal")
            if ($action -eq 0) { $list = Add-PasswordEntry -List $list; continue }
            break
        }
        
        # Lista
        Write-Host "  Senhas cadastradas:" -ForegroundColor White
        Write-Host ""
        for ($i = 0; $i -lt $list.Count; $i++) {
            $mark = if ($i -eq $defIdx) { " >> PADRAO" } else { "" }
            Write-Host "    $($i+1). $($list[$i].Name)$mark" -ForegroundColor $(if ($i -eq $defIdx) { "Cyan" } else { "Gray" })
        }
        Write-Host ""
        
        $action = Show-Menu -Title "Acoes:" -Options @("[A] Adicionar", "[D] Excluir", "[P] Definir como padrao", "[V] Voltar")
        
        $done = $false
        switch ($action) {
            0 { $list = Add-PasswordEntry -List $list }
            1 {
                $result = Remove-PasswordEntry -List $list -DefaultIndex ([ref]$defIdx)
                $list = $result.List
            }
            2 {
                $result = Set-DefaultPasswordEntry -List $list -DefaultIndex ([ref]$defIdx)
                $list = $result.List
            }
            3 { $done = $true }
        }
        if ($done) { break }
        
    } while ($true)
    
    Save-PasswordList -List $list -DefaultIndex $defIdx
}

function Add-PasswordEntry {
    param([array]$List)
    Write-Host ""
    Write-Info "Digite um nome para identificar a senha:"
    $name = Read-Host "    Nome"
    if ([string]::IsNullOrWhiteSpace($name)) { Write-Error "Nome invalido"; pause; return $List }
    
    Write-Host ""
    Write-Info "Digite a senha (caracteres ocultos):"
    $secure = Read-Host -AsSecureString
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $pass = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    
    if ([string]::IsNullOrEmpty($pass)) { Write-Error "Senha vazia"; pause; return $List }
    
    $entry = @{ Name = $name; Password = $pass }
    $List = $List + $entry
    Write-Success "Senha '$name' adicionada!"
    Start-Sleep -Milliseconds 500
    return $List
}

function Remove-PasswordEntry {
    param([array]$List, [ref]$DefaultIndex)
    Write-Host ""
    Write-Info "Digite o numero da senha para excluir:"
    $input = Read-Host "    Numero"
    $num = 0
    if ([int]::TryParse($input, [ref]$num) -and $num -ge 1 -and $num -le $List.Count) {
        $idx = $num - 1
        $name = $List[$idx].Name
        $List = @($List[0..($idx-1)]) + @($List[($idx+1)..($List.Count-1)])
        if ($DefaultIndex.Value -eq $idx) { $DefaultIndex.Value = -1 }
        elseif ($DefaultIndex.Value -gt $idx) { $DefaultIndex.Value-- }
        Write-Success "Senha '$name' excluida!"
    } else {
        Write-Error "Numero invalido"
    }
    Start-Sleep -Milliseconds 500
    return @{ List = $List; DefaultIndex = $DefaultIndex.Value }
}

function Set-DefaultPasswordEntry {
    param([array]$List, [ref]$DefaultIndex)
    Write-Host ""
    Write-Info "Digite o numero da senha para definir como padrao:"
    $input = Read-Host "    Numero"
    $num = 0
    if ([int]::TryParse($input, [ref]$num) -and $num -ge 1 -and $num -le $List.Count) {
        $DefaultIndex.Value = $num - 1
        Write-Success "Padrao alterado para: $($List[$DefaultIndex.Value].Name)"
    } else {
        Write-Error "Numero invalido"
    }
    Start-Sleep -Milliseconds 500
    return @{ List = $List; DefaultIndex = $DefaultIndex.Value }
}

# ── Seletor de senha com setas ──

function Read-PasswordInteractive {
    $data = Load-PasswordList
    $list = $data.List
    $defIdx = $data.DefaultIndex
    
    Write-Host ""
    Write-Host "  -----------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    
    $platDefaultPass = Get-PlatformDefaultPassword
    
    if ($list.Count -eq 0) {
        # Nenhuma cadastrada - mostra opcao padrao ou digitar
        Write-Host "  Usar senha padrao do $($script:CurrentPlatform)?" -ForegroundColor Yellow
        Write-Host "    Senha: $platDefaultPass" -ForegroundColor DarkGray
        Write-Host "    [S] Sim  |  [N] Digitar outra" -ForegroundColor Gray
        
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        $char = if ($null -ne $key -and $key.Character -ne 0) { $key.Character.ToString().ToLower() } else { "" }
        
        if ($char -eq 's') {
            Write-Host "  S" -ForegroundColor Cyan
            Write-Success "Usando senha padrao do $($script:CurrentPlatform)"
            return $platDefaultPass
        }
        Write-Host "  N" -ForegroundColor Gray
        return Read-ManualPassword
    }
    
    # Lista com setas
    $defName = if ($defIdx -ge 0 -and $defIdx -lt $list.Count) { $list[$defIdx].Name } else { "Nenhuma" }
    $defPass = if ($defIdx -ge 0 -and $defIdx -lt $list.Count) { $list[$defIdx].Password } else { $platDefaultPass }
    
    Write-Host "  Escolha a senha (setas ↑↓, Enter confirma):" -ForegroundColor Yellow
    Write-Host ""
    
    # Prepara opcoes: senhas cadastradas + opcao de digitar
    $options = @()
    foreach ($e in $list) {
        $mask = if ($e.Password.Length -gt 10) { "$($e.Password.Substring(0,4))****$($e.Password.Substring($e.Password.Length-4))" } else { "****" }
        $options += "$($e.Name) [$mask]"
    }
    $options += "[N] Digitar outra senha"
    $options += "[V] Voltar ao menu principal"
    
    # Exibe lista inicial
    for ($i = 0; $i -lt $options.Count; $i++) {
        Write-Host "     $($options[$i])" -ForegroundColor DarkGray
    }
    Write-Host ""
    $hintY = [Console]::CursorTop
    
    $selected = if ($defIdx -ge 0) { $defIdx } else { 0 }
    $menuTop = $hintY - $options.Count - 3
    
    do {
        for ($i = 0; $i -lt $options.Count; $i++) {
            $row = $menuTop + 2 + $i
            [Console]::SetCursorPosition(4, $row)
            if ($i -eq $selected) {
                Write-Host ">>" -NoNewline -ForegroundColor Cyan
                Write-Host " $($options[$i])" -ForegroundColor Cyan
            } else {
                Write-Host "  " -NoNewline
                Write-Host " $($options[$i])" -ForegroundColor DarkGray
            }
        }
        [Console]::SetCursorPosition(0, $hintY)
        Write-Host "  Use setas (cima/baixo), letras ou Enter" -NoNewline -ForegroundColor DarkGray
        [Console]::SetCursorPosition(0, $hintY)
        
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        if ($key.VirtualKeyCode -eq 38 -and $selected -gt 0) { $selected-- }
        elseif ($key.VirtualKeyCode -eq 40 -and $selected -lt $options.Count - 1) { $selected++ }
        elseif ($key.VirtualKeyCode -eq 13) { break }
        
    } while ($true)
    
    # Limpa hint
    [Console]::SetCursorPosition(0, $hintY)
    Write-Host "                                              " -NoNewline
    [Console]::SetCursorPosition(0, $hintY)
    
    if ($selected -eq $options.Count - 1) {
        # Voltar
        Write-Host "[V] Voltar ao menu principal" -ForegroundColor Gray
        return $null
    }
    
    if ($selected -eq $options.Count - 2) {
        # Escolheu "Digitar outra"
        Write-Host "[N] Digitar outra senha" -ForegroundColor Cyan
        return Read-ManualPassword
    }
    
    Write-Host ">> $($list[$selected].Name)" -ForegroundColor Cyan
    Write-Success "Senha selecionada: $($list[$selected].Name)"
    return $list[$selected].Password
}

function Read-ManualPassword {
    Write-Host ""
    Write-Host "  Digite a senha (oculta):" -ForegroundColor Yellow
    $secure = Read-Host -AsSecureString
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $pass = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    
    if ([string]::IsNullOrEmpty($pass)) {
        Write-Error "Vazia. Usando senha padrao do $($script:CurrentPlatform)."
        return Get-PlatformDefaultPassword
    }
    return $pass
}

# ── PDF to BLOB SQLite ──

function Get-Sqlite3 {
    $scriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path $MyInvocation.MyCommand.Path -Parent } else { (Get-Location).Path }
    $libDir = Join-Path $scriptDir "lib"
    $sqlite3 = Join-Path $libDir "sqlite3.exe"

    if (Test-Path $sqlite3) { return $sqlite3 }

    Write-Host ""
    Write-Info "sqlite3.exe nao encontrado. Baixando automaticamente..."
    Write-Host ""

    New-Item -ItemType Directory -Path $libDir -Force | Out-Null

    $zipUrl = "https://www.sqlite.org/2026/sqlite-tools-win-x64-3530300.zip"
    $zipPath = Join-Path $libDir "sqlite-tools.zip"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Info "Baixando de sqlite.org..."
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
    } catch {
        Write-Error "Falha ao baixar: $($_.Exception.Message)"
        return $null
    }

    $found = $false
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName -eq "sqlite3.exe") {
                $out = Join-Path $libDir "sqlite3.exe"
                $s = $entry.Open()
                $b = New-Object byte[] $entry.Length
                $s.Read($b, 0, $b.Length) | Out-Null
                $s.Close()
                [System.IO.File]::WriteAllBytes($out, $b)
                Write-Info "Extraido: sqlite3.exe"
                $found = $true
                break
            }
        }
        $zip.Dispose()
    } catch {
        Write-Error "Falha ao extrair: $($_.Exception.Message)"
        try { $zip.Dispose() } catch { }
    }

    Remove-Item $zipPath -Force

    if ($found -and (Test-Path $sqlite3)) {
        Write-Success "sqlite3.exe instalado em: $libDir"
        return $sqlite3
    }

    Write-Error "Falha ao baixar sqlite3.exe. Baixe manualmente de: https://www.sqlite.org/download.html"
    return $null
}

function Get-InfracaoFromFilename {
    param([string]$FileName)
    $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    if ($nameNoExt.Length -ge 5) {
        $code = $nameNoExt.Substring(0, 5)
        $isNum = [int]::TryParse($code, [ref]$null)
        if ($isNum -or $code.ToLower() -eq "0000a") { return $code }
    }
    return $null
}

function Invoke-PdfToBlob {
    param([string[]]$PdfFiles, [string]$OutputDir, [string]$Password, [bool]$Encrypt)

    Write-Host ""
    Write-Host "  -----------------------------------" -ForegroundColor DarkGray
    Write-Host "  Convertendo PDF(s) para SQLite BLOB..." -ForegroundColor White
    Write-Host ""

    $sqlite3 = Get-Sqlite3
    if (-not $sqlite3) {
        Write-Error "sqlite3.exe nao disponivel."
        pause
        return
    }

    $entries = @()
    foreach ($f in $PdfFiles) {
        $name = Split-Path $f -Leaf
        $code = Get-InfracaoFromFilename -FileName $name
        if ($code) {
            $entries += @{ File = $f; Name = $name; Code = $code }
        } else {
            Write-Host "  [!] Ignorado (codigo nao reconhecido): $name" -ForegroundColor DarkYellow
        }
    }

    if ($entries.Count -eq 0) {
        Write-Error "Nenhum PDF valido encontrado. O nome deve comecar com 5 digitos (ex: 51691_Compressed.pdf)"
        pause
        return
    }

    Write-Host "  $($entries.Count) PDF(s) validos para processar" -ForegroundColor White
    Write-Host ""

    $dbPath = if ($Encrypt) {
        [System.IO.Path]::Combine($OutputDir, "fch")
    } else {
        [System.IO.Path]::Combine($OutputDir, "fch.sqlite")
    }
    $tempDb = if ($Encrypt) { [System.IO.Path]::Combine($OutputDir, "fch_temp.sqlite") } else { $dbPath }

    if (Test-Path $tempDb) { Remove-Item $tempDb -Force }
    if ($Encrypt -and (Test-Path "$dbPath.sqlite")) { Remove-Item "$dbPath.sqlite" -Force }

    try {
        & $sqlite3 $tempDb "CREATE TABLE IF NOT EXISTS fichas (infracao TEXT, arquivo BLOB);"

        $total = $entries.Count
        $ok = 0; $fail = 0

        for ($i = 0; $i -lt $total; $i++) {
            $e = $entries[$i]
            Write-Host "  [$($i+1)/$total] " -NoNewline -ForegroundColor Cyan
            Write-Host "$($e.Name) -> " -NoNewline
            Write-Host "cod $($e.Code)" -ForegroundColor DarkGray

            $escapedCode = $e.Code -replace "'", "''"
            $sql = "INSERT INTO fichas (infracao, arquivo) VALUES('$escapedCode', readfile('$($e.File)'));"

            & $sqlite3 $tempDb $sql
            if ($LASTEXITCODE -eq 0) {
                $ok++
                Write-Host "    -> OK" -ForegroundColor Green
            } else {
                $fail++
                Write-Host "    -> FALHA" -ForegroundColor Red
            }
        }

        Write-Host ""
        Write-Success "$ok registro(s) inserido(s)"
        if ($fail -gt 0) { Write-Warning "$falha falha(s)" }

        if ($Encrypt) {
            Write-Host ""
            Write-Info "Encriptando SQLite com AES-128-CBC..."
            $dbBytes = [System.IO.File]::ReadAllBytes($tempDb)
            $encBytes = Invoke-B4XEncrypt -Data $dbBytes -Password $Password
            [System.IO.File]::WriteAllBytes($dbPath + ".en", $encBytes)
            Remove-Item $tempDb -Force
            Write-Success "Arquivo encriptado: fch.en"
        } else {
            Write-Success "Arquivo gerado: fch.sqlite"
        }

    } catch {
        Write-Error "Falha: $($_.Exception.Message)"
        if (Test-Path $tempDb) { Remove-Item $tempDb -Force }
    }
    Write-Host ""
    Write-Host "  -----------------------------------" -ForegroundColor DarkGray
    pause
}

# ── Processamento ──

function Invoke-InteractiveProcess {
    param([string[]]$Files, [string]$OutputDir, [string]$Password, [string]$Mode)
    
    $ok = 0; $fail = 0; $total = $Files.Count
    Write-Host ""
    Write-Host "  -----------------------------------" -ForegroundColor DarkGray
    Write-Host "  Processando $total arquivo(s)..." -ForegroundColor White
    
    for ($i = 0; $i -lt $total; $i++) {
        $file = $Files[$i]
        $name = Split-Path $file -Leaf
        Write-Host ""
        Write-Host "  [$($i+1)/$total] $name" -ForegroundColor Cyan
        try {
            if ($Mode -eq "Encrypt") {
                # Nome completo do arquivo encriptado (incluindo extensão) sempre em minúsculas
                $encName = ("$name.en").ToLowerInvariant()
                $out = [System.IO.Path]::Combine($OutputDir, $encName)
                $raw = [System.IO.File]::ReadAllBytes($file)
                $enc = Invoke-B4XEncrypt -Data $raw -Password $Password
                [System.IO.File]::WriteAllBytes($out, $enc)
                Write-Success $encName
                $ok++
            } else {
                if (-not $name.EndsWith(".en")) { Write-Error "Ignorado (sem extensao .en)"; $fail++; continue }
                $decName = $name -replace '\.en$', ''
                $out = [System.IO.Path]::Combine($OutputDir, $decName)
                $encBytes = [System.IO.File]::ReadAllBytes($file)
                $dec = Invoke-B4XDecrypt -Data $encBytes -Password $Password
                [System.IO.File]::WriteAllBytes($out, $dec)
                Write-Success "$decName"
                $ok++
            }
        } catch {
            Write-Error "Falha: $($_.Exception.Message)"
            $fail++
        }
    }
    
    Write-Host ""
    Write-Host "  -----------------------------------" -ForegroundColor DarkGray
    Write-Host "  Concluido: $ok sucesso(s), $fail falha(s)" -ForegroundColor $(if ($fail -eq 0){"Green"}else{"Yellow"})
    Write-Host ""
}

# ── Main ──

function Start-Interactive {
    $scriptLocation = if ($MyInvocation.MyCommand.Path) { Split-Path $MyInvocation.MyCommand.Path -Parent } else { (Get-Location).Path }
    
    do {
        Write-Header
        $toggleLabel = if ($script:CurrentPlatform -eq "iOS") { "Android" } else { "iOS" }
        Write-Host "  Escolha a operacao:" -ForegroundColor White
        Write-Host ""
        $opts = @("[1] ENCRIPTAR arquivo(s)", "[2] DECRIPTAR arquivo(s)", "[P] PDF to BLOB SQLite (iOS)", "[3] GERENCIAR SENHAS", "[T] Alternar para $toggleLabel", "[4] SAIR")
        $choice = Show-Menu -Title "" -Options $opts
        
        if ($choice -eq 5) {
            Write-Host ""; Write-Host "  Encerrando. Ate logo!" -ForegroundColor Cyan; break
        }
        
        if ($choice -eq 4) {
            $script:CurrentPlatform = if ($script:CurrentPlatform -eq "iOS") { "Android" } else { "iOS" }
            continue
        }
        
        if ($choice -eq 3) {
            Show-PasswordManager
            continue
        }
        
        if ($choice -eq 2) {
            # PDF to BLOB SQLite
            Write-Header
            Write-Host "  Modo: " -NoNewline; Write-Host "PDF to BLOB SQLite (iOS)" -ForegroundColor Magenta
            Write-Host ""
            Write-Info "Abrindo seletor de PDFs..."
            
            $pdfFiles = Select-Files -Title "Selecionar PDFs" -Filter "PDF (*.pdf)|*.pdf|Todos (*.*)|*.*" -InitialDir $scriptLocation
            
            if (-not $pdfFiles) {
                Write-Error "Nenhum arquivo selecionado"
                Write-Host "  Pressione qualquer tecla..." -ForegroundColor DarkGray
                $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
                continue
            }
            Write-Success "$($pdfFiles.Count) PDF(s) selecionado(s)"
            
            $initialOut = if ($pdfFiles.Count -eq 1) { Split-Path $pdfFiles[0] -Parent } else { $scriptLocation }
            if ([string]::IsNullOrEmpty($initialOut)) { $initialOut = $scriptLocation }
            
            Write-Host ""
            Write-Info "Diretorio de saida?"
            Write-Host "    [S] Escolher outra pasta  |  [N] Mesma pasta dos PDFs" -ForegroundColor Gray
            $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            $charOut = if ($null -ne $key -and $key.Character -ne 0) { $key.Character.ToString().ToLower() } else { "" }
            
            $outputDir = if ($charOut -eq 's') {
                $d = Select-Folder -Desc "Pasta de saida" -InitialDir $initialOut
                if ([string]::IsNullOrEmpty($d)) { $initialOut } else { $d }
            } else { $initialOut }
            
            if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
            Write-Info "Saida: $outputDir"
            
            Write-Host ""
            Write-Host "  Encriptar o SQLite gerado?" -ForegroundColor Yellow
            Write-Host "    [S] Sim (gera fch.en)  |  [N] Nao (gera fch.sqlite)" -ForegroundColor Gray
            $key2 = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            $charEnc = if ($null -ne $key2 -and $key2.Character -ne 0) { $key2.Character.ToString().ToLower() } else { "" }
            $encryptDb = ($charEnc -eq 's')
            
            $pass = ""
            if ($encryptDb) {
                Write-Host ""
                Write-Info "Escolha a senha para encriptar o SQLite:"
                $pass = Read-PasswordInteractive
                if ($null -eq $pass) { continue }
            }
            
            Invoke-PdfToBlob -PdfFiles $pdfFiles -OutputDir $outputDir -Password $pass -Encrypt $encryptDb
            continue
        }
        
        $mode = if ($choice -eq 0) { "Encrypt" } else { "Decrypt" }
        $modeLabel = if ($mode -eq "Encrypt") { "ENCRIPTAR" } else { "DECRIPTAR" }
        
        # Arquivos
        Write-Header
        Write-Host "  Modo: " -NoNewline; Write-Host $modeLabel -ForegroundColor Cyan
        Write-Host ""
        Write-Info "Abrindo seletor de arquivos..."
        
        $filter = if ($mode -eq "Decrypt") { "Arquivos .en (*.en)|*.en|Todos (*.*)|*.*" } else { "Todos os arquivos (*.*)|*.*" }
        $files = Select-Files -Title "Selecionar para $modeLabel" -Filter $filter -InitialDir $scriptLocation
        
        if (-not $files) {
            Write-Error "Nenhum arquivo selecionado"
            Write-Host "  Pressione qualquer tecla..." -ForegroundColor DarkGray
            $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
            continue
        }
        Write-Success "$($files.Count) arquivo(s) selecionado(s)"
        
        # Saida
        if ($files.Count -eq 1) {
            $initialOut = Split-Path $files[0] -Parent
            if ([string]::IsNullOrEmpty($initialOut)) { $initialOut = $scriptLocation }
        } else {
            $initialOut = $scriptLocation
        }
        
        Write-Host ""
        Write-Info "Diretorio de saida?"
        Write-Host "    [S] Escolher outra pasta  |  [N] Mesma pasta dos arquivos" -ForegroundColor Gray
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        $charOut = if ($null -ne $key -and $key.Character -ne 0) { $key.Character.ToString().ToLower() } else { "" }
        
        # Senha
        $pass = Read-PasswordInteractive
        if ($null -eq $pass) { continue }
        
        if ($charOut -eq 's') {
            $outputDir = Select-Folder -Desc "Pasta de saida" -InitialDir $initialOut
            if ([string]::IsNullOrEmpty($outputDir)) { $outputDir = $initialOut }
            if ([string]::IsNullOrEmpty($outputDir)) { $outputDir = $scriptLocation }
            
            Write-Info "Saida unificada: $outputDir"
            if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
            
            Invoke-InteractiveProcess -Files $files -OutputDir $outputDir -Password $pass -Mode $mode
        } else {
            Write-Host ""
            Write-Info "Salvando cada arquivo em sua propria pasta"
            $ok = 0; $fail = 0
            foreach ($f in $files) {
                $name = Split-Path $f -Leaf
                $parent = Split-Path $f -Parent
                Write-Host ""
                Write-Host "  [$($ok+$fail+1)/$($files.Count)] $name" -ForegroundColor Cyan
                try {
                    if ($mode -eq "Encrypt") {
                        # Nome completo do arquivo encriptado (incluindo extensão) sempre em minúsculas
                        $encName = ("$name.en").ToLowerInvariant()
                        $out = [System.IO.Path]::Combine($parent, $encName)
                        $raw = [System.IO.File]::ReadAllBytes($f)
                        $enc = Invoke-B4XEncrypt -Data $raw -Password $pass
                        [System.IO.File]::WriteAllBytes($out, $enc)
                        Write-Success $encName; $ok++
                    } else {
                        if (-not $name.EndsWith(".en")) { Write-Error "Ignorado"; $fail++; continue }
                        $decName = $name -replace '\.en$', ''
                        $out = [System.IO.Path]::Combine($parent, $decName)
                        [System.IO.File]::WriteAllBytes($out, (Invoke-B4XDecrypt -Data ([System.IO.File]::ReadAllBytes($f)) -Password $pass))
                        Write-Success "$decName"; $ok++
                    }
                } catch { Write-Error "Falha: $($_.Exception.Message)"; $fail++ }
            }
            Write-Host ""
            Write-Host "  -----------------------------------" -ForegroundColor DarkGray
            Write-Host "  Concluido: $ok sucesso(s), $fail falha(s)" -ForegroundColor $(if ($fail -eq 0){"Green"}else{"Yellow"})
            Write-Host ""
        }
        
        Write-Host "  [Enter] Voltar ao menu  |  [Esc] Sair" -ForegroundColor DarkGray
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        if ($key.VirtualKeyCode -eq 27) { Write-Host "  Ate logo!" -ForegroundColor Cyan; break }
    } while ($true)
}

Start-Interactive
