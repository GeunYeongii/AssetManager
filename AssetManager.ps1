# ==============================================================================
# PowerShell 완전 보안 자산 관리자 (AES-256 + 동적 테이블 너비 자동 정렬)
# ==============================================================================

$DataFile = "$PSScriptRoot\SecureAssets.dat"
$Global:SessionPassword = $null

# 1. AES-256 + PBKDF2 (SHA-256, 50,000 Rounds) 암호화 함수
function Encrypt-Aes256 {
    param(
        [string]$PlainText,
        [string]$Password
    )
    $salt = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($salt)

    $iv = New-Object byte[] 16
    $rng.GetBytes($iv)

    # PBKDF2 키 유도 (50,000회 반복, SHA-256)
    $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 50000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $deriveBytes.GetBytes(32) # 256-bit

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv

    $encryptor = $aes.CreateEncryptor()
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $cipherBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

    # 헤더: "SAM1" (4B) + Salt (16B) + IV (16B) + CipherData
    $magic = [System.Text.Encoding]::ASCII.GetBytes("SAM1")
    $result = New-Object byte[] ($magic.Length + $salt.Length + $iv.Length + $cipherBytes.Length)
    [System.Buffer]::BlockCopy($magic, 0, $result, 0, $magic.Length)
    [System.Buffer]::BlockCopy($salt, 0, $result, $magic.Length, $salt.Length)
    [System.Buffer]::BlockCopy($iv, 0, $result, $magic.Length + $salt.Length, $iv.Length)
    [System.Buffer]::BlockCopy($cipherBytes, 0, $result, $magic.Length + $salt.Length + $iv.Length, $cipherBytes.Length)

    return [System.Convert]::ToBase64String($result)
}

# 2. AES-256 복호화 함수
function Decrypt-Aes256 {
    param(
        [string]$EncryptedBase64,
        [string]$Password
    )
    $rawBytes = [System.Convert]::FromBase64String($EncryptedBase64)
    if ($rawBytes.Length -lt 36) {
        throw [System.Security.Cryptography.CryptographicException]::new("유효하지 않은 데이터 포맷입니다.")
    }

    $magic = [System.Text.Encoding]::ASCII.GetString($rawBytes, 0, 4)
    if ($magic -ne "SAM1") {
        throw [System.Security.Cryptography.CryptographicException]::new("지원되지 않거나 손상된 암호화 데이터입니다.")
    }

    $salt = New-Object byte[] 16
    [System.Buffer]::BlockCopy($rawBytes, 4, $salt, 0, 16)

    $iv = New-Object byte[] 16
    [System.Buffer]::BlockCopy($rawBytes, 20, $iv, 0, 16)

    $cipherLength = $rawBytes.Length - 36
    $cipherBytes = New-Object byte[] $cipherLength
    [System.Buffer]::BlockCopy($rawBytes, 36, $cipherBytes, 0, $cipherLength)

    $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 50000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $deriveBytes.GetBytes(32)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv

    $decryptor = $aes.CreateDecryptor()
    $plainBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)
    return [System.Text.Encoding]::UTF8.GetString($plainBytes)
}

# 레거시 DPAPI 복호화 보조 함수 (최초 1회 마이그레이션용)
function Unprotect-LegacyDpapi {
    param([string]$EncryptedText)
    $Secure = ConvertTo-SecureString -String $EncryptedText
    $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
    $PlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($Ptr)
    return $PlainText
}

# 3. 비밀번호 마스킹 입력 함수 (*** 표시)
function Read-MaskedInput {
    param(
        [string]$PromptText = " ▶ 비밀번호를 입력하세요",
        [bool]$IsEditMode = $false
    )
    Write-Host -NoNewline "$($PromptText): "
    $pwd = ""
    while ($true) {
        $key = [System.Console]::ReadKey($true)
        if ($key.Key -eq [System.ConsoleKey]::Enter) {
            Write-Host ""
            break
        } elseif ($key.Key -eq [System.ConsoleKey]::Backspace) {
            if ($pwd.Length -gt 0) {
                $pwd = $pwd.Substring(0, $pwd.Length - 1)
                Write-Host -NoNewline "`b `b"
            }
        } elseif ($key.Key -eq [System.ConsoleKey]::Escape) {
            Write-Host ""
            if ($IsEditMode) { return "" }
            throw [System.Exception]::new("CANCEL_ACTION")
        } elseif ([char]::IsControl($key.KeyChar)) {
            continue
        } else {
            $pwd += $key.KeyChar
            Write-Host -NoNewline "*"
        }
    }
    
    if (-not $IsEditMode -and ($pwd -eq 'q' -or $pwd -eq 'Q' -or $pwd -eq 'ㅂ')) {
        throw [System.Exception]::new("CANCEL_ACTION")
    }
    return $pwd
}

# 4. 데이터 정규화 함수 (CLI/GUI AccessType 보장 및 윈도우 administrator 역할 root 통일)
function Normalize-Asset {
    param($raw)
    $accList = @()
    if ($raw.PSObject.Properties['Accounts'] -and $raw.Accounts) {
        $rawAccounts = if ($raw.Accounts -is [array]) { @($raw.Accounts) } else { @($raw.Accounts) }
        foreach ($acc in $rawAccounts) {
            $accessType = if ($acc.PSObject.Properties['AccessType'] -and $acc.AccessType) { [string]$acc.AccessType } else { "CLI" }
            $accId = [string]$acc.ID
            
            $role = "-"
            if ($accessType.ToUpper() -eq "CLI") {
                if ($accId.ToLower() -eq "root" -or $accId.ToLower() -eq "administrator") {
                    $role = "root"
                } else {
                    $role = if ($acc.AccountType -and $acc.AccountType -ne "-") { [string]$acc.AccountType } else { "일반" }
                }
            }

            $accList += [PSCustomObject]@{
                AccountID   = if ($acc.AccountID) { [string]$acc.AccountID } else { [guid]::NewGuid().ToString() }
                AccessType  = $accessType
                AccountType = $role
                ID          = $accId
                PW          = [string]$acc.PW
                Description = if ($acc.Description) { [string]$acc.Description } else { "" }
            }
        }
    } elseif ($raw.PSObject.Properties['ID'] -or $raw.PSObject.Properties['PW']) {
        if ($raw.ID -or $raw.PW) {
            $accId = [string]$raw.ID
            $role = if ($accId.ToLower() -eq "root" -or $accId.ToLower() -eq "administrator") { "root" } else { "일반" }
            $accList += [PSCustomObject]@{
                AccountID   = [guid]::NewGuid().ToString()
                AccessType  = "CLI"
                AccountType = $role
                ID          = $accId
                PW          = [string]$raw.PW
                Description = "기존 등록 계정"
            }
        }
    }

    return [PSCustomObject]@{
        AssetID   = if ($raw.AssetID) { [string]$raw.AssetID } else { [guid]::NewGuid().ToString() }
        AssetName = [string]$raw.AssetName
        IP        = [string]$raw.IP
        WebURL    = [string]$raw.WebURL
        Note      = [string]$raw.Note
        Accounts  = $accList
    }
}

# 5. 자산 불러오기 (AES-256 + 정규화)
function Get-Assets {
    if (-not (Test-Path $DataFile)) { return @() }
    try {
        $EncryptedText = (Get-Content $DataFile -Raw).Trim()
        if ([string]::IsNullOrWhiteSpace($EncryptedText)) { return @() }
        $PlainText = Decrypt-Aes256 -EncryptedBase64 $EncryptedText -Password $Global:SessionPassword
        $result = $PlainText | ConvertFrom-Json
        $normalized = @()
        if ($result -is [array]) {
            foreach ($item in $result) { $normalized += (Normalize-Asset -raw $item) }
        } elseif ($null -ne $result) {
            $normalized += (Normalize-Asset -raw $result)
        }
        return $normalized
    } catch {
        Write-Warning "자산 데이터 복호화 실패: $($_.Exception.Message)"
        return @()
    }
}

# 6. 자산 저장하기 (AES-256)
function Save-Assets {
    param([array]$Assets)
    if ($Assets.Count -eq 0) {
        $JsonText = '[]'
    } else {
        $JsonText = ConvertTo-Json -InputObject @($Assets) -Depth 5 -Compress
    }
    $EncryptedText = Encrypt-Aes256 -PlainText $JsonText -Password $Global:SessionPassword
    [System.IO.File]::WriteAllText($DataFile, $EncryptedText, [System.Text.UTF8Encoding]::new($false))
}

# 7. 동일 AccessType(CLI/GUI) 내 계정 ID 중복 검사 함수
function Test-AccountExists {
    param(
        [array]$Accounts,
        [string]$AccessType,
        [string]$CheckID
    )
    if (-not $Accounts -or $Accounts.Count -eq 0) { return $false }
    $normCheck = $CheckID.Trim().ToLower()
    $normAccess = $AccessType.Trim().ToUpper()
    foreach ($acc in $Accounts) {
        if ($acc.AccessType.ToUpper() -eq $normAccess -and $acc.ID.Trim().ToLower() -eq $normCheck) {
            return $true
        }
    }
    return $false
}

# 8. CLI 계정 전체에서 root 역할 존재 여부 검사 함수
function Test-HasCliRootRole {
    param([array]$Accounts)
    if (-not $Accounts -or $Accounts.Count -eq 0) { return $false }
    foreach ($acc in $Accounts) {
        if ($acc.AccessType.ToUpper() -eq "CLI") {
            $idLower = $acc.ID.Trim().ToLower()
            $roleLower = $acc.AccountType.Trim().ToLower()
            if ($roleLower -eq "root" -or $idLower -eq "root" -or $idLower -eq "administrator") {
                return $true
            }
        }
    }
    return $false
}

# 9. 한글 및 영문 너비 계산용 유틸리티
function Get-DisplayWidth {
    param([string]$str)
    if ($null -eq $str) { return 0 }
    $width = 0
    foreach ($c in $str.ToCharArray()) {
        $code = [int]$c
        if (($code -ge 0xAC00 -and $code -le 0xD7A3) -or 
            ($code -ge 0x1100 -and $code -le 0x11FF) -or 
            ($code -ge 0x3130 -and $code -le 0x318F) -or 
            ($code -ge 0x3200 -and $code -le 0x32FF) -or 
            ($code -ge 0x3400 -and $code -le 0x4DBF) -or 
            ($code -ge 0x4E00 -and $code -le 0x9FFF) -or 
            ($code -ge 0xF900 -and $code -le 0xFAFF) -or 
            ($code -ge 0xFF00 -and $code -le 0xFFEF)) {
            $width += 2
        } else {
            $width += 1
        }
    }
    return $width
}

function Pad-RightDisplay {
    param([string]$str, [int]$totalWidth)
    if ($null -eq $str) { $str = "" }
    $w = Get-DisplayWidth $str
    $pad = $totalWidth - $w
    if ($pad -gt 0) { return $str + (" " * $pad) }
    return $str
}

# 10. UI 공통 배너
function Show-Banner {
    param([string]$Title, [string]$Color = "Cyan")
    Write-Host " ╔═════════════════════════════════════════════════════════════╗" -ForegroundColor $Color
    $w = Get-DisplayWidth "[ $Title ]"
    $leftPad = [Math]::Floor((61 - $w) / 2)
    $rightPad = 61 - $w - $leftPad
    $line = " ║" + (" " * $leftPad) + "[ $Title ]" + (" " * $rightPad) + "║"
    Write-Host $line -ForegroundColor $Color
    Write-Host " ╚═════════════════════════════════════════════════════════════╝`n" -ForegroundColor $Color
}

# 11. 사용자 입력 처리
function Read-Input {
    param(
        [string]$PromptText,
        [bool]$AllowEmpty = $false,
        [bool]$IsEditMode = $false
    )
    $val = (Read-Host $PromptText).Trim()
    
    if ($val -eq 'q' -or $val -eq 'Q' -or $val -eq 'ㅂ') {
        throw [System.Exception]::new("CANCEL_ACTION")
    }
    
    if ($val -eq '' -and -not $AllowEmpty -and -not $IsEditMode) {
        throw [System.Exception]::new("CANCEL_ACTION")
    }
    
    return $val
}

# 12. 프로그램 시작: 마스터 비밀번호 인증 및 세션 활성화
function Initialize-SessionAuth {
    Clear-Host

    $needsMigration = $false
    $migratedAssets = @()

    if (Test-Path $DataFile) {
        $rawContent = (Get-Content $DataFile -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($rawContent)) {
            $isAesFormat = $false
            try {
                $testBytes = [System.Convert]::FromBase64String($rawContent)
                if ($testBytes.Length -ge 4) {
                    $magic = [System.Text.Encoding]::ASCII.GetString($testBytes, 0, 4)
                    if ($magic -eq "SAM1") { $isAesFormat = $true }
                }
            } catch { $isAesFormat = $false }

            if (-not $isAesFormat) {
                try {
                    $legacyPlain = Unprotect-LegacyDpapi -EncryptedText $rawContent
                    $parsed = $legacyPlain | ConvertFrom-Json
                    if ($parsed -is [array]) {
                        foreach ($p in $parsed) { $migratedAssets += (Normalize-Asset -raw $p) }
                    } elseif ($null -ne $parsed) {
                        $migratedAssets += (Normalize-Asset -raw $parsed)
                    }
                    $needsMigration = $true
                } catch {
                    $needsMigration = $false
                }
            }
        }
    }

    if ((-not (Test-Path $DataFile)) -or $needsMigration) {
        Show-Banner -Title "AssetManager 초기 설정" -Color "Yellow"
        if ($needsMigration) {
            Write-Host " [*] 기존 자산 데이터($($migratedAssets.Count)건)를 감지했습니다." -ForegroundColor Green
            Write-Host " [*] 데이터를 보호할 '마스터 비밀번호'를 설정해주세요." -ForegroundColor Yellow
        } else {
            Write-Host " [!] 최초 실행입니다. 사용할 '마스터 비밀번호'를 설정하세요." -ForegroundColor Yellow
        }
        Write-Host " [★] 중요: 비밀번호를 분실하면 어떤 방법으로도 데이터를 복구할 수 없습니다!`n" -ForegroundColor Red
        
        while ($true) {
            $pwd1 = Read-MaskedInput -PromptText " ▶ 마스터 비밀번호 설정 (최소 6자리)"
            if ([string]::IsNullOrWhiteSpace($pwd1)) {
                Write-Host " [!] 비밀번호는 공백일 수 없습니다.`n" -ForegroundColor Red
                continue
            }
            if ($pwd1.Length -lt 6) {
                Write-Host " [!] 보안을 위해 비밀번호는 최소 6자리 이상이어야 합니다.`n" -ForegroundColor Red
                continue
            }
            
            $pwd2 = Read-MaskedInput -PromptText " ▶ 마스터 비밀번호 확인"
            if ($pwd1 -ne $pwd2) {
                Write-Host " [!] 비밀번호가 일치하지 않습니다. 다시 입력해주세요.`n" -ForegroundColor Red
                continue
            }
            
            $Global:SessionPassword = $pwd1
            Save-Assets -Assets $migratedAssets
            Write-Host "`n [v] 보안 저장소가 안전하게 설정되었습니다!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            break
        }
        return
    }

    $encryptedContent = (Get-Content $DataFile -Raw).Trim()
    $maxAttempts = 5
    $attempts = 0

    while ($attempts -lt $maxAttempts) {
        Clear-Host
        Show-Banner -Title "AssetManager 로그인" -Color "Cyan"
        Write-Host " 🔐 자산 관리자에 접속하려면 마스터 비밀번호를 입력하세요.`n" -ForegroundColor White
        
        $inputPwd = Read-MaskedInput -PromptText " ▶ 마스터 비밀번호"
        
        if ([string]::IsNullOrEmpty($inputPwd)) {
            Write-Host " [!] 비밀번호를 입력해주세요." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            continue
        }

        try {
            $null = Decrypt-Aes256 -EncryptedBase64 $encryptedContent -Password $inputPwd
            $Global:SessionPassword = $inputPwd
            Write-Host "`n [v] 인증 성공! 자산 관리자를 시작합니다." -ForegroundColor Green
            Start-Sleep -Milliseconds 600
            return
        } catch {
            $attempts++
            $remain = $maxAttempts - $attempts
            Write-Host "`n [!] 비밀번호가 일치하지 않습니다. (남은 횟수: $remain 회)" -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }

    Write-Host "`n [!] 5회 연속 인증 실패로 보안을 위해 프로그램을 강제 종료합니다." -ForegroundColor Red
    Start-Sleep -Seconds 2
    exit
}

# 13. 마스터 비밀번호 변경
function Change-MasterPasswordFlow {
    try {
        Clear-Host
        Show-Banner -Title "마스터 비밀번호 변경" -Color "Magenta"
        Write-Host " [*] 변경 시 모든 자산 데이터가 새로운 마스터 키로 재암호화됩니다.`n" -ForegroundColor Cyan

        $currPwd = Read-MaskedInput -PromptText " ▶ 현재 마스터 비밀번호 확인"
        if ($currPwd -ne $Global:SessionPassword) {
            Write-Host "`n [!] 현재 비밀번호가 일치하지 않습니다." -ForegroundColor Red
            $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
            return
        }

        $newPwd1 = Read-MaskedInput -PromptText "`n ▶ 변경할 새 마스터 비밀번호 (최소 6자리)"
        if ([string]::IsNullOrWhiteSpace($newPwd1) -or $newPwd1.Length -lt 6) {
            Write-Host "`n [!] 새 비밀번호는 최소 6자리 이상이어야 합니다." -ForegroundColor Red
            $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
            return
        }

        $newPwd2 = Read-MaskedInput -PromptText " ▶ 변경할 새 마스터 비밀번호 확인"
        if ($newPwd1 -ne $newPwd2) {
            Write-Host "`n [!] 새 비밀번호가 일치하지 않습니다." -ForegroundColor Red
            $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
            return
        }

        $assets = @(Get-Assets)
        $Global:SessionPassword = $newPwd1
        Save-Assets -Assets $assets

        Write-Host "`n [v] 모든 자산 데이터가 새 비밀번호로 안전하게 재암호화되었습니다!" -ForegroundColor Green
        $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
    } catch {
        Write-Host "`n [!] 비밀번호 변경 중 오류가 발생했습니다: $($_.Exception.Message)" -ForegroundColor Red
        $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
    }
}

# 14. 전체/검색 자산 요약 목록 출력 함수 (동적 컬럼 너비 계산 적용)
function Show-AssetSummaryTable {
    param([array]$AssetList)

    if ($AssetList.Count -eq 0) { return }

    # 각 컬럼의 최소 보장 너비
    $wNo   = 6   # "번호"
    $wName = 8   # "자산명"
    $wIP   = 8   # "IP주소"
    $wAccs = 16  # "등록 계정 요약"
    $wURL  = 10  # "접속URL"
    $wNote = 6   # "비고"

    $rows = @()

    for ($i = 0; $i -lt $AssetList.Count; $i++) {
        $a = $AssetList[$i]
        $noStr = ($i + 1).ToString()

        $cliAccs = @($a.Accounts | Where-Object { $_.AccessType -eq "CLI" })
        $guiAccs = @($a.Accounts | Where-Object { $_.AccessType -eq "GUI" })

        $summaryParts = @()
        if ($cliAccs.Count -gt 0) {
            $first = $cliAccs[0].ID
            $cliStr = if ($cliAccs.Count -eq 1) { "CLI:$first" } else { "CLI:$first 외 $($cliAccs.Count - 1)" }
            $summaryParts += $cliStr
        }
        if ($guiAccs.Count -gt 0) {
            $first = $guiAccs[0].ID
            $guiStr = if ($guiAccs.Count -eq 1) { "GUI:$first" } else { "GUI:$first 외 $($guiAccs.Count - 1)" }
            $summaryParts += $guiStr
        }

        $accSummary = if ($summaryParts.Count -gt 0) { $summaryParts -join " | " } else { "계정 없음" }
        $urlStr = if ($a.WebURL) { $a.WebURL } else { "-" }
        $noteStr = if ($a.Note) { $a.Note } else { "-" }

        $rowItem = [PSCustomObject]@{
            NoStr      = $noStr
            NameStr    = $a.AssetName
            IPStr      = $a.IP
            AccSummary = $accSummary
            URLStr     = $urlStr
            NoteStr    = $noteStr
        }
        $rows += $rowItem

        # 최대 너비 계산 (데이터 너비 + 2 여백)
        $wNo   = [Math]::Max($wNo, (Get-DisplayWidth $noStr) + 2)
        $wName = [Math]::Max($wName, (Get-DisplayWidth $a.AssetName) + 2)
        $wIP   = [Math]::Max($wIP, (Get-DisplayWidth $a.IP) + 2)
        $wAccs = [Math]::Max($wAccs, (Get-DisplayWidth $accSummary) + 2)
        $wURL  = [Math]::Max($wURL, (Get-DisplayWidth $urlStr) + 2)
        $wNote = [Math]::Max($wNote, (Get-DisplayWidth $noteStr) + 2)
    }

    # 헤더 및 동적 구분선 생성
    $hNo   = Pad-RightDisplay "번호" $wNo
    $hName = Pad-RightDisplay "자산명" $wName
    $hIP   = Pad-RightDisplay "IP주소" $wIP
    $hAccs = Pad-RightDisplay "등록 계정 요약" $wAccs
    $hURL  = Pad-RightDisplay "접속URL" $wURL
    $hNote = Pad-RightDisplay "비고" $wNote

    $sepNo   = "─" * ($wNo - 1)
    $sepName = "─" * ($wName - 1)
    $sepIP   = "─" * ($wIP - 1)
    $sepAccs = "─" * ($wAccs - 1)
    $sepURL  = "─" * ($wURL - 1)
    $sepNote = "─" * ($wNote - 1)

    Write-Host " $hNo $hName $hIP $hAccs $hURL $hNote" -ForegroundColor DarkGray
    Write-Host " $sepNo $sepName $sepIP $sepAccs $sepURL $sepNote" -ForegroundColor DarkGray

    # 데이터 행 출력
    foreach ($r in $rows) {
        $cNo   = Pad-RightDisplay $r.NoStr $wNo
        $cName = Pad-RightDisplay $r.NameStr $wName
        $cIP   = Pad-RightDisplay $r.IPStr $wIP
        $cAccs = Pad-RightDisplay $r.AccSummary $wAccs
        $cURL  = Pad-RightDisplay $r.URLStr $wURL
        $cNote = Pad-RightDisplay $r.NoteStr $wNote

        Write-Host " $cNo $cName $cIP $cAccs $cURL $cNote" -ForegroundColor White
    }
}

# 15. 계정 목록 테이블 동적 너비 출력 공통 헬퍼
function Show-AccountListTable {
    param([array]$Accounts)

    if (-not $Accounts -or $Accounts.Count -eq 0) {
        Write-Host "   (등록된 계정이 없습니다. [1]번을 눌러 새 계정을 추가하세요.)" -ForegroundColor Gray
        return
    }

    $wNo   = 6   # "번호"
    $wAcc  = 10  # "접근유형"
    $wType = 12  # "구분/역할"
    $wID   = 12  # "계정 ID"
    $wPW   = 14  # "패스워드"
    $wDesc = 14  # "계정 설명/메모"

    $rows = @()
    for ($i = 0; $i -lt $Accounts.Count; $i++) {
        $acc = $Accounts[$i]
        $noStr = ($i + 1).ToString()
        $accTypeStr = if ($acc.AccessType) { "[$($acc.AccessType)]" } else { "[CLI]" }
        $roleStr = if ($acc.AccessType.ToUpper() -eq "GUI") { "[-]" } elseif ($acc.AccountType -and $acc.AccountType -ne "-") { "[$($acc.AccountType)]" } else { "[-]" }
        $pwStr = if ($acc.PW) { $acc.PW } else { "-" }
        $descStr = if ($acc.Description) { $acc.Description } else { "-" }

        $rows += [PSCustomObject]@{
            NoStr   = $noStr
            AccStr  = $accTypeStr
            RoleStr = $roleStr
            IDStr   = $acc.ID
            PWStr   = $pwStr
            DescStr = $descStr
        }

        $wNo   = [Math]::Max($wNo, (Get-DisplayWidth $noStr) + 2)
        $wAcc  = [Math]::Max($wAcc, (Get-DisplayWidth $accTypeStr) + 2)
        $wType = [Math]::Max($wType, (Get-DisplayWidth $roleStr) + 2)
        $wID   = [Math]::Max($wID, (Get-DisplayWidth $acc.ID) + 2)
        $wPW   = [Math]::Max($wPW, (Get-DisplayWidth $pwStr) + 2)
        $wDesc = [Math]::Max($wDesc, (Get-DisplayWidth $descStr) + 2)
    }

    $hNo   = Pad-RightDisplay "번호" $wNo
    $hAcc  = Pad-RightDisplay "접근유형" $wAcc
    $hType = Pad-RightDisplay "구분/역할" $wType
    $hID   = Pad-RightDisplay "계정 ID" $wID
    $hPW   = Pad-RightDisplay "패스워드" $wPW
    $hDesc = Pad-RightDisplay "계정 설명/메모" $wDesc

    $sepNo   = "─" * ($wNo - 1)
    $sepAcc  = "─" * ($wAcc - 1)
    $sepType = "─" * ($wType - 1)
    $sepID   = "─" * ($wID - 1)
    $sepPW   = "─" * ($wPW - 1)
    $sepDesc = "─" * ($wDesc - 1)

    Write-Host "  $hNo $hAcc $hType $hID $hPW $hDesc" -ForegroundColor DarkGray
    Write-Host "  $sepNo $sepAcc $sepType $sepID $sepPW $sepDesc" -ForegroundColor DarkGray

    foreach ($r in $rows) {
        $cNo   = Pad-RightDisplay $r.NoStr $wNo
        $cAcc  = Pad-RightDisplay $r.AccStr $wAcc
        $cType = Pad-RightDisplay $r.RoleStr $wType
        $cID   = Pad-RightDisplay $r.IDStr $wID
        $cPW   = Pad-RightDisplay $r.PWStr $wPW
        $cDesc = Pad-RightDisplay $r.DescStr $wDesc

        Write-Host "  $cNo $cAcc $cType $cID $cPW $cDesc" -ForegroundColor White
    }
}

# 16. 자산 검색 (다중 계정 ID/타입/접속유형/설명까지 검색)
function Search-Assets {
    param([array]$AllAssets, [string]$Keyword)
    $isIPLike = $Keyword -match '^[\d\.\:]+$'
    if ($isIPLike) {
        $results = $AllAssets | Where-Object {
            $_.IP -like "*$Keyword*" -or $_.WebURL -like "*$Keyword*"
        }
        Write-Host "`n [*] IP/URL 검색 모드로 동작합니다. (검색어: '$Keyword')" -ForegroundColor Cyan
    } else {
        $results = $AllAssets | Where-Object {
            $foundInAcc = $false
            if ($_.Accounts) {
                foreach ($acc in $_.Accounts) {
                    if ($acc.ID -like "*$Keyword*" -or 
                        $acc.AccountType -like "*$Keyword*" -or 
                        $acc.AccessType -like "*$Keyword*" -or 
                        $acc.Description -like "*$Keyword*" -or 
                        $acc.PW -like "*$Keyword*") {
                        $foundInAcc = $true
                        break
                    }
                }
            }
            $_.AssetName -like "*$Keyword*" -or $_.Note -like "*$Keyword*" -or $foundInAcc
        }
        Write-Host "`n [*] 통합 텍스트 검색 모드로 동작합니다. (검색어: '$Keyword')" -ForegroundColor Cyan
    }
    return @($results)
}

# 17. 단일 계정 정보 입력 헬퍼 (CLI는 root/일반 관리, GUI는 역할 미사용)
function Read-NewAccountInput {
    param(
        [array]$ExistingAccounts,
        [string]$HeaderMessage = "새 계정 정보 입력"
    )
    Write-Host "`n [ $HeaderMessage ] ('q' 입력 시 취소)" -ForegroundColor Cyan
    
    # 1. 접속 유형 선택 (CLI vs GUI)
    Write-Host " ▶ 접속 유형을 선택하세요:" -ForegroundColor White
    Write-Host "   [1] CLI (SSH/Telnet/Console/RDP)" -ForegroundColor DarkGray
    Write-Host "   [2] GUI (웹콘솔)" -ForegroundColor DarkGray
    $typeChoice = (Read-Host "   번호 선택 (기본값: 1)").Trim()
    
    $accessType = "CLI"
    if ($typeChoice -eq '2' -or $typeChoice.ToLower() -eq 'gui') {
        $accessType = "GUI"
    }

    $accRole = "-"

    if ($accessType -eq "GUI") {
        # ── GUI 웹콘솔 계정 입력 (역할 개념 없음) ──
        $accID = ""
        while ($true) {
            $accID = Read-Input " ▶ 계정 ID"
            if (Test-AccountExists -Accounts $ExistingAccounts -AccessType "GUI" -CheckID $accID) {
                Write-Host " [!] [GUI]에 이미 '$accID' 계정이 등록되어 있습니다. 다른 ID를 입력하세요.`n" -ForegroundColor Red
                continue
            }
            break
        }
        $accRole = "-"
    } else {
        # ── CLI 원격/콘솔 계정 입력 (root 고유성 관리) ──
        $hasCliRoot = Test-HasCliRootRole -Accounts $ExistingAccounts

        $accID = ""
        while ($true) {
            $accID = Read-Input " ▶ 계정 ID"
            $normId = $accID.ToLower()

            # CLI에 이미 root가 있는데 root 또는 administrator 추가 시도시 차단
            if (($normId -eq "root" -or $normId -eq "administrator") -and $hasCliRoot) {
                Write-Host " [!] [CLI]에 이미 root(관리자) 계정이 등록되어 있습니다. 일반 계정 ID를 입력하세요.`n" -ForegroundColor Red
                continue
            }
            
            if (Test-AccountExists -Accounts $ExistingAccounts -AccessType "CLI" -CheckID $accID) {
                Write-Host " [!] [CLI]에 이미 '$accID' 계정이 등록되어 있습니다. 다른 ID를 입력하세요.`n" -ForegroundColor Red
                continue
            }
            break
        }

        # CLI 역할 결정
        if ($accID.ToLower() -eq "root" -or $accID.ToLower() -eq "administrator") {
            $accRole = "root"
        } elseif ($hasCliRoot) {
            $accRole = "일반"
            Write-Host " [*] [CLI]에 이미 관리자(root) 계정이 존재하여 역할이 자동으로 '일반'으로 지정됩니다." -ForegroundColor DarkGray
        } else {
            $inRole = Read-Input " ▶ 계정 구분/역할" -AllowEmpty $true
            if ([string]::IsNullOrWhiteSpace($inRole)) {
                $accRole = "일반"
            } else {
                $accRole = $inRole
            }
        }
    }

    # 패스워드 입력 (* 마스킹)
    $accPW = Read-MaskedInput -PromptText " ▶ 패스워드"
    $accDesc = Read-Input " ▶ 계정 설명/메모" -AllowEmpty $true

    return [PSCustomObject]@{
        AccountID   = [guid]::NewGuid().ToString()
        AccessType  = $accessType
        AccountType = $accRole
        ID          = $accID
        PW          = $accPW
        Description = $accDesc
    }
}

# 18. 자산 상세 정보 및 하위 계정 관리 화면 (동적 너비 계정 테이블 출력)
function Show-AssetDetailManage {
    param([string]$AssetID)

    while ($true) {
        $allAssets = @(Get-Assets)
        $targetAsset = $allAssets | Where-Object { $_.AssetID -eq $AssetID }
        if (-not $targetAsset) {
            Write-Host "`n [!] 해당 자산을 찾을 수 없습니다." -ForegroundColor Red
            Start-Sleep -Seconds 1
            return
        }

        Clear-Host
        Show-Banner -Title "자산 상세 정보 & 계정 관리" -Color "Green"

        Write-Host " [ 자산 기본 정보 ]" -ForegroundColor Cyan
        Write-Host "  * 자산명 : $($targetAsset.AssetName)" -ForegroundColor White
        Write-Host "  * IP 주소: $($targetAsset.IP)" -ForegroundColor White
        Write-Host "  * 접속URL: $($targetAsset.WebURL)" -ForegroundColor White
        Write-Host "  * 비고   : $($targetAsset.Note)" -ForegroundColor White
        Write-Host " ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

        $accList = @($targetAsset.Accounts)
        Write-Host " [ 등록된 계정 목록 (총 $($accList.Count)개) ]" -ForegroundColor Yellow

        # 동적 너비 계정 목록 테이블 출력
        Show-AccountListTable -Accounts $accList

        Write-Host "`n ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "   [1] 새 계정 추가              [2] 계정 수정" -ForegroundColor White
        Write-Host "   [3] 계정 삭제                 [0] 이전 화면으로 돌아가기" -ForegroundColor White
        Write-Host " ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

        while ([Console]::KeyAvailable) { [Console]::ReadKey($true) | Out-Null }
        Write-Host ""
        $action = (Read-Host " ▶ 작업을 선택하세요").Trim()

        switch ($action) {
            # ── 1. 계정 추가 ──
            '1' {
                try {
                    $newAcc = Read-NewAccountInput -ExistingAccounts $targetAsset.Accounts -HeaderMessage "새 계정 추가"

                    for ($i = 0; $i -lt $allAssets.Count; $i++) {
                        if ($allAssets[$i].AssetID -eq $AssetID) {
                            $allAssets[$i].Accounts += $newAcc
                            break
                        }
                    }
                    Save-Assets -Assets $allAssets
                    Write-Host "`n [v] 계정이 성공적으로 추가되었습니다." -ForegroundColor Green
                    Start-Sleep -Seconds 1
                } catch {
                    if ($_.Exception.Message -eq "CANCEL_ACTION") {
                        Write-Host "`n [-] 취소되었습니다." -ForegroundColor Yellow
                        Start-Sleep -Milliseconds 600
                    } else { throw $_ }
                }
            }

            # ── 2. 계정 수정 ──
            '2' {
                try {
                    if ($accList.Count -eq 0) {
                        Write-Host "`n [!] 수정할 계정이 없습니다." -ForegroundColor Yellow
                        Start-Sleep -Seconds 1
                        break
                    }
                    $selNo = Read-Input " ▶ 수정할 계정 번호를 입력하세요"
                    $idx = [int]$selNo - 1
                    if ($idx -lt 0 -or $idx -ge $accList.Count) {
                        Write-Host " [!] 올바른 번호가 아닙니다." -ForegroundColor Red
                        Start-Sleep -Seconds 1
                        break
                    }

                    $targetAcc = $accList[$idx]
                    $isCliRoot = ($targetAcc.AccessType.ToUpper() -eq "CLI" -and ($targetAcc.AccountType.ToLower() -eq "root" -or $targetAcc.ID.ToLower() -eq "root" -or $targetAcc.ID.ToLower() -eq "administrator"))

                    Write-Host "`n [*] 수정할 값을 입력하세요. (기존 유지 시 Enter, 취소 시 q)" -ForegroundColor Cyan

                    if ($isCliRoot) {
                        # CLI root 계정 수정
                        Write-Host " [*] CLI 관리자(root) 계정 수정 모드입니다. 계정 ID와 역할([root])은 자동 유지됩니다." -ForegroundColor Yellow
                        
                        $uPW = Read-MaskedInput -PromptText " ▶ 변경할 패스워드 (기존 유지 시 Enter)" -IsEditMode $true
                        $uDesc = Read-Input " ▶ 계정 설명/메모 [$($targetAcc.Description)]" -IsEditMode $true

                        for ($i = 0; $i -lt $allAssets.Count; $i++) {
                            if ($allAssets[$i].AssetID -eq $AssetID) {
                                for ($j = 0; $j -lt $allAssets[$i].Accounts.Count; $j++) {
                                    if ($allAssets[$i].Accounts[$j].AccountID -eq $targetAcc.AccountID) {
                                        if ($uPW)   { $allAssets[$i].Accounts[$j].PW = $uPW }
                                        if ($uDesc) { $allAssets[$i].Accounts[$j].Description = $uDesc }
                                        break
                                    }
                                }
                                break
                            }
                        }
                    } elseif ($targetAcc.AccessType.ToUpper() -eq "GUI") {
                        # GUI 계정 수정 (역할 개념 없음)
                        $uID = Read-Input " ▶ 계정 ID [$($targetAcc.ID)]" -IsEditMode $true
                        $finalID = if ($uID) { $uID } else { $targetAcc.ID }

                        if ($uID) {
                            $otherAccounts = @($targetAsset.Accounts | Where-Object { $_.AccountID -ne $targetAcc.AccountID })
                            if (Test-AccountExists -Accounts $otherAccounts -AccessType "GUI" -CheckID $finalID) {
                                Write-Host "`n [!] [GUI]에 이미 '$finalID' 계정이 등록되어 있어 변경할 수 없습니다." -ForegroundColor Red
                                Start-Sleep -Seconds 1
                                break
                            }
                        }

                        $uPW   = Read-MaskedInput -PromptText " ▶ 패스워드 (기존 유지 시 Enter)" -IsEditMode $true
                        $uDesc = Read-Input " ▶ 계정 설명/메모 [$($targetAcc.Description)]" -IsEditMode $true

                        for ($i = 0; $i -lt $allAssets.Count; $i++) {
                            if ($allAssets[$i].AssetID -eq $AssetID) {
                                for ($j = 0; $j -lt $allAssets[$i].Accounts.Count; $j++) {
                                    if ($allAssets[$i].Accounts[$j].AccountID -eq $targetAcc.AccountID) {
                                        if ($uID)   { $allAssets[$i].Accounts[$j].ID = $finalID }
                                        if ($uPW)   { $allAssets[$i].Accounts[$j].PW = $uPW }
                                        if ($uDesc) { $allAssets[$i].Accounts[$j].Description = $uDesc }
                                        break
                                    }
                                }
                                break
                            }
                        }
                    } else {
                        # CLI 일반 계정 수정
                        $uID = Read-Input " ▶ 계정 ID [$($targetAcc.ID)]" -IsEditMode $true
                        $finalID = if ($uID) { $uID } else { $targetAcc.ID }

                        if ($finalID.ToLower() -eq "root" -or $finalID.ToLower() -eq "administrator") {
                            $hasRootAlready = Test-HasCliRootRole -Accounts @($targetAsset.Accounts | Where-Object { $_.AccountID -ne $targetAcc.AccountID })
                            if ($hasRootAlready) {
                                Write-Host "`n [!] [CLI]에 이미 root 계정이 존재하므로 일반 계정을 root로 변경할 수 없습니다." -ForegroundColor Red
                                Start-Sleep -Seconds 1
                                break
                            }
                        }

                        if ($uID) {
                            $otherAccounts = @($targetAsset.Accounts | Where-Object { $_.AccountID -ne $targetAcc.AccountID })
                            if (Test-AccountExists -Accounts $otherAccounts -AccessType "CLI" -CheckID $finalID) {
                                Write-Host "`n [!] [CLI]에 이미 '$finalID' 계정이 등록되어 있어 변경할 수 없습니다." -ForegroundColor Red
                                Start-Sleep -Seconds 1
                                break
                            }
                        }

                        $uRole = Read-Input " ▶ 계정 구분/역할 [$($targetAcc.AccountType)]" -IsEditMode $true
                        $uPW   = Read-MaskedInput -PromptText " ▶ 패스워드 (기존 유지 시 Enter)" -IsEditMode $true
                        $uDesc = Read-Input " ▶ 계정 설명/메모 [$($targetAcc.Description)]" -IsEditMode $true

                        for ($i = 0; $i -lt $allAssets.Count; $i++) {
                            if ($allAssets[$i].AssetID -eq $AssetID) {
                                for ($j = 0; $j -lt $allAssets[$i].Accounts.Count; $j++) {
                                    if ($allAssets[$i].Accounts[$j].AccountID -eq $targetAcc.AccountID) {
                                        if ($uID)   { $allAssets[$i].Accounts[$j].ID = $finalID }
                                        if ($uRole) { $allAssets[$i].Accounts[$j].AccountType = $uRole }
                                        if ($uPW)   { $allAssets[$i].Accounts[$j].PW = $uPW }
                                        if ($uDesc) { $allAssets[$i].Accounts[$j].Description = $uDesc }
                                        break
                                    }
                                }
                                break
                            }
                        }
                    }

                    Save-Assets -Assets $allAssets
                    Write-Host "`n [v] 계정 정보가 성공적으로 수정되었습니다." -ForegroundColor Green
                    Start-Sleep -Seconds 1
                } catch {
                    if ($_.Exception.Message -eq "CANCEL_ACTION") {
                        Write-Host "`n [-] 취소되었습니다." -ForegroundColor Yellow
                        Start-Sleep -Milliseconds 600
                    } else { throw $_ }
                }
            }

            # ── 3. 계정 삭제 ──
            '3' {
                try {
                    if ($accList.Count -eq 0) {
                        Write-Host "`n [!] 삭제할 계정이 없습니다." -ForegroundColor Yellow
                        Start-Sleep -Seconds 1
                        break
                    }
                    $selNo = Read-Input " ▶ 삭제할 계정 번호를 입력하세요"
                    $idx = [int]$selNo - 1
                    if ($idx -lt 0 -or $idx -ge $accList.Count) {
                        Write-Host " [!] 올바른 번호가 아닙니다." -ForegroundColor Red
                        Start-Sleep -Seconds 1
                        break
                    }

                    $targetAcc = $accList[$idx]
                    $roleLabel = if ($targetAcc.AccessType.ToUpper() -eq "GUI") { "" } else { "[$($targetAcc.AccountType)] " }
                    $confirm = Read-Input " ▶ '[$($targetAcc.AccessType)] $roleLabel$($targetAcc.ID)' 계정을 삭제하시겠습니까? (Y/N)" -AllowEmpty $true
                    if ($confirm -match '^[Yy]$') {
                        for ($i = 0; $i -lt $allAssets.Count; $i++) {
                            if ($allAssets[$i].AssetID -eq $AssetID) {
                                $allAssets[$i].Accounts = @($allAssets[$i].Accounts | Where-Object { $_.AccountID -ne $targetAcc.AccountID })
                                break
                            }
                        }
                        Save-Assets -Assets $allAssets
                        Write-Host "`n [v] 계정이 삭제되었습니다." -ForegroundColor Green
                        Start-Sleep -Seconds 1
                    }
                } catch {
                    if ($_.Exception.Message -eq "CANCEL_ACTION") {
                        Write-Host "`n [-] 취소되었습니다." -ForegroundColor Yellow
                        Start-Sleep -Milliseconds 600
                    } else { throw $_ }
                }
            }

            # ── 0. 뒤로가기 ──
            '0' {
                return
            }

            default {}
        }
    }
}

# ─────────────────────────────────────────────────────────────
# 19. 메인 프로그램 시작: 세션 인증
# ─────────────────────────────────────────────────────────────
Initialize-SessionAuth

# 20. 메인 메뉴 루프
while ($true) {
    Clear-Host
    Show-Banner -Title "AssetManager" -Color "Cyan"
    
    Write-Host "   [1] 자산 검색                 [2] 자산 조회 (전체)" -ForegroundColor White
    Write-Host "   [3] 자산 추가                 [4] 자산 기본정보 수정" -ForegroundColor White
    Write-Host "   [5] 자산 삭제                 [6] 마스터 비밀번호 변경" -ForegroundColor White
    Write-Host "   [0] 프로그램 종료" -ForegroundColor DarkGray
    Write-Host " ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    
    while ([Console]::KeyAvailable) { [Console]::ReadKey($true) | Out-Null }
    Write-Host ""
    $choice = (Read-Host " ▶ 메뉴 번호를 선택하세요").Trim()

    $assets = @(Get-Assets)

    switch ($choice) {
        # ── 1. 자산 검색 ──
        '1' {
            try {
                Clear-Host
                Show-Banner -Title "자 산 검 색" -Color "Green"
                Write-Host " [*] 빈칸 Enter 또는 'q'를 누르면 메인 메뉴로 돌아갑니다.`n" -ForegroundColor Gray
                
                if ($assets.Count -eq 0) {
                    Write-Host " [!] 등록된 자산이 없습니다." -ForegroundColor Yellow
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                    break
                }
                
                $keyword = Read-Input " ▶ 검색어를 입력하세요 (IP, 자산명, 계정ID, 역할 등)"
                
                $results = @(Search-Assets -AllAssets $assets -Keyword $keyword)
                if ($results.Count -eq 0) {
                    Write-Host " [!] 검색 결과가 없습니다." -ForegroundColor Yellow
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                } else {
                    Write-Host "`n [ 검색 결과 (총 $($results.Count)건) ]" -ForegroundColor Green
                    Show-AssetSummaryTable -AssetList $results
                    Write-Host "`n [*] 상세 조회 및 계정 관리할 자산 번호를 입력하세요. (메뉴 이동: Enter)" -ForegroundColor Cyan
                    $detailSel = (Read-Host " ▶ 번호 입력").Trim()
                    if ($detailSel -ne '') {
                        $selIdx = [int]$detailSel - 1
                        if ($selIdx -ge 0 -and $selIdx -lt $results.Count) {
                            Show-AssetDetailManage -AssetID $results[$selIdx].AssetID
                        } else {
                            Write-Host " [!] 잘못된 번호입니다." -ForegroundColor Red
                            Start-Sleep -Seconds 1
                        }
                    }
                }
            } catch {
                if ($_.Exception.Message -eq "CANCEL_ACTION") {
                    Write-Host "`n [-] 메인 메뉴로 돌아갑니다." -ForegroundColor Yellow
                    Start-Sleep -Milliseconds 600
                } else { throw $_ }
            }
        }

        # ── 2. 자산 조회 (전체) ──
        '2' { 
            Clear-Host
            Show-Banner -Title "전체 자산 목록" -Color "Green"
            
            if ($assets.Count -eq 0) {
                Write-Host " [!] 등록된 자산이 없습니다." -ForegroundColor Yellow
                $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
            } else {
                Show-AssetSummaryTable -AssetList $assets
                Write-Host "`n 총 자산 수: $($assets.Count) 건" -ForegroundColor Gray
                Write-Host " [*] 상세 조회 및 계정 관리할 자산 번호를 입력하세요. (메뉴 이동: Enter)" -ForegroundColor Cyan
                $detailSel = (Read-Host " ▶ 번호 입력").Trim()
                if ($detailSel -ne '') {
                    $selIdx = [int]$detailSel - 1
                    if ($selIdx -ge 0 -and $selIdx -lt $assets.Count) {
                        Show-AssetDetailManage -AssetID $assets[$selIdx].AssetID
                    } else {
                        Write-Host " [!] 잘못된 번호입니다." -ForegroundColor Red
                        Start-Sleep -Seconds 1
                    }
                }
            }
        }

        # ── 3. 자산 추가 (IP 선입력 & 기존 자산 자동 매칭) ──
        '3' { 
            try {
                Clear-Host
                Show-Banner -Title "자 산 추 가" -Color "Yellow"
                Write-Host " [*] 취소하려면 언제든 'q'를 입력하거나 빈칸에서 Enter를 누르세요.`n" -ForegroundColor Gray
                
                # 1단계: IP 주소 먼저 입력
                $inputIP = Read-Input " ▶ 1. IP 주소 입력"

                # 기존에 등록된 IP 자산 검색
                $existingAsset = $assets | Where-Object { $_.IP.Trim() -eq $inputIP.Trim() }

                if ($existingAsset) {
                    # ── CASE A: 이미 등록된 IP인 경우 ──
                    Write-Host "`n [!] 이미 등록된 IP 자산을 발견했습니다!" -ForegroundColor Green
                    Write-Host " ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
                    Write-Host "  * 자산명 : $($existingAsset.AssetName)" -ForegroundColor White
                    Write-Host "  * IP 주소: $($existingAsset.IP)" -ForegroundColor White
                    Write-Host "  * 접속URL: $($existingAsset.WebURL)" -ForegroundColor White
                    Write-Host "  * 비고   : $($existingAsset.Note)" -ForegroundColor White
                    
                    $currAccounts = @($existingAsset.Accounts)
                    $accSummaryStr = ""
                    if ($currAccounts.Count -eq 0) {
                        $accSummaryStr = "등록된 계정 없음"
                    } else {
                        $accNames = $currAccounts | ForEach-Object { 
                            if ($_.AccessType.ToUpper() -eq "GUI") { "GUI:$($_.ID)" } else { "CLI:$($_.ID)($($_.AccountType))" }
                        }
                        $accSummaryStr = $accNames -join ", "
                    }
                    Write-Host "  * 현재 등록된 계정 ($($currAccounts.Count)개): $accSummaryStr" -ForegroundColor Yellow
                    Write-Host " ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

                    $isCorrect = Read-Input " ▶ 이 자산이 맞습니까? (Y/N)" -AllowEmpty $true
                    if ($isCorrect -notmatch '^[Yy]$') {
                        Write-Host "`n [-] 자산 추가가 취소되었습니다." -ForegroundColor Yellow
                        $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                        break
                    }

                    Write-Host "`n [*] '$($existingAsset.AssetName)' 자산에 새 계정을 추가합니다. (접속URL 등은 자동 유지됩니다)" -ForegroundColor Cyan
                    
                    $extraNote = Read-Input " ▶ 추가할 비고/메모 (기존 유지 시 Enter)" -AllowEmpty $true -IsEditMode $true
                    if ($extraNote) {
                        for ($i = 0; $i -lt $assets.Count; $i++) {
                            if ($assets[$i].AssetID -eq $existingAsset.AssetID) {
                                if ([string]::IsNullOrWhiteSpace($assets[$i].Note)) {
                                    $assets[$i].Note = $extraNote
                                } else {
                                    $assets[$i].Note += " / $extraNote"
                                }
                                break
                            }
                        }
                    }

                    # 계정 추가 루프
                    $addedCount = 0
                    while ($true) {
                        $targetForAcc = $assets | Where-Object { $_.AssetID -eq $existingAsset.AssetID }
                        $newAcc = Read-NewAccountInput -ExistingAccounts $targetForAcc.Accounts -HeaderMessage "추가할 계정 정보 입력"
                        
                        for ($i = 0; $i -lt $assets.Count; $i++) {
                            if ($assets[$i].AssetID -eq $existingAsset.AssetID) {
                                $assets[$i].Accounts += $newAcc
                                break
                            }
                        }
                        $addedCount++
                        Save-Assets -Assets $assets
                        Write-Host "`n [v] [$($newAcc.AccessType)] '$($newAcc.ID)' 계정이 성공적으로 추가되었습니다!" -ForegroundColor Green

                        $more = Read-Input "`n ▶ 이 자산에 계정을 더 추가하시겠습니까? (Y/N)" -AllowEmpty $true
                        if ($more -notmatch '^[Yy]$') {
                            break
                        }
                    }

                    Write-Host "`n [v] 총 $addedCount 개의 계정이 추가 완료되었습니다." -ForegroundColor Green
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                } else {
                    # ── CASE B: 신규 IP인 경우 ──
                    $inputName = Read-Input " ▶ 2. 자산 이름"
                    $inputURL  = Read-Input " ▶ 3. 접속 URL (없을 시 Enter)" -AllowEmpty $true
                    $inputNote = Read-Input " ▶ 4. 비고/메모 (없을 시 Enter)" -AllowEmpty $true

                    # 첫 번째 계정 등록
                    $newAccounts = @()
                    $firstAcc = Read-NewAccountInput -ExistingAccounts $newAccounts -HeaderMessage "첫 번째 계정 정보 등록"
                    $newAccounts += $firstAcc

                    # 추가 계정 연속 등록 여부
                    while ($true) {
                        $more = Read-Input "`n ▶ 이 자산에 계정을 더 추가하시겠습니까? (Y/N)" -AllowEmpty $true
                        if ($more -notmatch '^[Yy]$') {
                            $nextAcc = Read-NewAccountInput -ExistingAccounts $newAccounts -HeaderMessage "추가 계정 정보 등록"
                            $newAccounts += $nextAcc
                        } else {
                            break
                        }
                    }

                    $newAsset = [PSCustomObject]@{
                        AssetID   = [guid]::NewGuid().ToString()
                        AssetName = $inputName
                        IP        = $inputIP
                        WebURL    = $inputURL
                        Note      = $inputNote
                        Accounts  = $newAccounts
                    }

                    $assets += $newAsset
                    Save-Assets -Assets $assets
                    Write-Host "`n [v] 새 자산 '$inputName' 및 계정 $($newAccounts.Count)개가 성공적으로 등록되었습니다!" -ForegroundColor Green
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                }
            } catch {
                if ($_.Exception.Message -eq "CANCEL_ACTION") {
                    Write-Host "`n [-] 자산 추가가 취소되어 메인 메뉴로 돌아갑니다." -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                } else { throw $_ }
            }
        }

        # ── 4. 자산 기본정보 수정 ──
        '4' { 
            try {
                Clear-Host
                Show-Banner -Title "자산 기본정보 수정" -Color "Magenta"
                Write-Host " [*] 검색 및 대상 선택 중 빈칸 Enter 또는 'q'를 입력하면 취소됩니다.`n" -ForegroundColor Gray
                
                if ($assets.Count -eq 0) {
                    Write-Host " [!] 등록된 자산이 없습니다." -ForegroundColor Yellow
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                    break
                }
                
                $keyword = Read-Input " ▶ 수정할 자산을 검색하세요"
                $results = @(Search-Assets -AllAssets $assets -Keyword $keyword)
                if ($results.Count -eq 0) {
                    Write-Host " [!] 검색 결과가 없습니다." -ForegroundColor Yellow
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                    break
                }

                Write-Host "`n [ 검색 결과 ]" -ForegroundColor Green
                Show-AssetSummaryTable -AssetList $results
                Write-Host ""

                $selNum = Read-Input " ▶ 수정할 자산의 번호를 입력하세요"
                $selIdx = [int]$selNum - 1
                if ($selIdx -lt 0 -or $selIdx -ge $results.Count) {
                    Write-Host " [!] 잘못된 번호입니다." -ForegroundColor Red
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                    break
                }

                $selected = $results[$selIdx]
                $origIdx = -1
                for ($i = 0; $i -lt $assets.Count; $i++) {
                    if ($assets[$i].AssetID -eq $selected.AssetID) { $origIdx = $i; break }
                }

                Write-Host "`n [*] 수정할 값을 입력하세요. (기존 유지 시 Enter, 취소 시 q)" -ForegroundColor Cyan
                $newName = Read-Input " ▶ 1. 자산 이름 [$($assets[$origIdx].AssetName)]" -IsEditMode $true
                if ($newName) { $assets[$origIdx].AssetName = $newName }

                $newIP = Read-Input " ▶ 2. IP 주소 [$($assets[$origIdx].IP)]" -IsEditMode $true
                if ($newIP) { $assets[$origIdx].IP = $newIP }

                $newURL = Read-Input " ▶ 3. 접속 URL [$($assets[$origIdx].WebURL)]" -IsEditMode $true
                if ($newURL) { $assets[$origIdx].WebURL = $newURL }

                $newNote = Read-Input " ▶ 4. 비고/메모 [$($assets[$origIdx].Note)]" -IsEditMode $true
                if ($newNote) { $assets[$origIdx].Note = $newNote }

                Save-Assets -Assets $assets
                Write-Host "`n [v] 자산 기본정보가 수정되었습니다." -ForegroundColor Green
                Write-Host " [*] 계정(ID/PW) 수정을 원하시면 [2]번 조회 메뉴에서 해당 자산을 선택하세요." -ForegroundColor Yellow
                $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
            } catch {
                if ($_.Exception.Message -eq "CANCEL_ACTION") {
                    Write-Host "`n [-] 자산 수정이 취소되어 메인 메뉴로 돌아갑니다." -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                } else { throw $_ }
            }
        }

        # ── 5. 자산 / 계정 삭제 (선택적 삭제 지원) ──
        '5' { 
            try {
                Clear-Host
                Show-Banner -Title "자산 / 계정 삭제" -Color "Red"
                Write-Host " [*] 취소하려면 언제든 'q'를 입력하거나 빈칸에서 Enter를 누르세요.`n" -ForegroundColor Gray
                
                if ($assets.Count -eq 0) {
                    Write-Host " [!] 등록된 자산이 없습니다." -ForegroundColor Yellow
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                    break
                }
                
                $keyword = Read-Input " ▶ 삭제할 자산을 검색하세요"
                $results = @(Search-Assets -AllAssets $assets -Keyword $keyword)
                if ($results.Count -eq 0) {
                    Write-Host " [!] 검색 결과가 없습니다." -ForegroundColor Yellow
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                    break
                }

                Write-Host "`n [ 검색 결과 ]" -ForegroundColor Green
                Show-AssetSummaryTable -AssetList $results
                Write-Host ""

                $selNum = Read-Input " ▶ 삭제할 대상 자산의 번호를 입력하세요"
                $selIdx = [int]$selNum - 1
                if ($selIdx -lt 0 -or $selIdx -ge $results.Count) {
                    Write-Host " [!] 잘못된 번호입니다." -ForegroundColor Red
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                    break
                }

                $selected = $results[$selIdx]
                $accList = @($selected.Accounts)

                # 자산에 등록된 계정이 2개 이상인 경우 선택지 제공
                if ($accList.Count -ge 2) {
                    Clear-Host
                    Show-Banner -Title "삭제 옵션 선택" -Color "Red"
                    Write-Host " [ 대상 자산: $($selected.AssetName) ($($selected.IP)) ]" -ForegroundColor Cyan
                    Write-Host " ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
                    
                    # 동적 너비 계정 목록 테이블 출력
                    Show-AccountListTable -Accounts $accList

                    Write-Host "`n ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
                    Write-Host "   [1] 특정 계정만 선택하여 삭제" -ForegroundColor Yellow
                    Write-Host "   [2] 이 자산 전체 및 모든 계정 일괄 삭제" -ForegroundColor Red
                    Write-Host "   [0] 삭제 취소 (메인 메뉴로 이동)" -ForegroundColor DarkGray
                    Write-Host " ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

                    $delChoice = (Read-Host " ▶ 작업을 선택하세요").Trim()
                    if ($delChoice -eq '1') {
                        $delAccNo = Read-Input " ▶ 삭제할 계정 번호를 입력하세요"
                        $delIdx = [int]$delAccNo - 1
                        if ($delIdx -ge 0 -and $delIdx -lt $accList.Count) {
                            $targetAcc = $accList[$delIdx]
                            $roleLabel = if ($targetAcc.AccessType.ToUpper() -eq "GUI") { "" } else { "[$($targetAcc.AccountType)] " }
                            $confirm = Read-Input " ▶ '[$($targetAcc.AccessType)] $roleLabel$($targetAcc.ID)' 계정을 삭제하시겠습니까? (Y/N)" -AllowEmpty $true
                            if ($confirm -match '^[Yy]$') {
                                for ($i = 0; $i -lt $assets.Count; $i++) {
                                    if ($assets[$i].AssetID -eq $selected.AssetID) {
                                        $assets[$i].Accounts = @($assets[$i].Accounts | Where-Object { $_.AccountID -ne $targetAcc.AccountID })
                                        break
                                    }
                                }
                                Save-Assets -Assets $assets
                                Write-Host "`n [v] 계정이 성공적으로 삭제되었습니다." -ForegroundColor Green
                            } else {
                                Write-Host "`n [-] 삭제가 취소되었습니다." -ForegroundColor Yellow
                            }
                        } else {
                            Write-Host " [!] 올바른 계정 번호가 아닙니다." -ForegroundColor Red
                        }
                        $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                    } elseif ($delChoice -eq '2') {
                        $confirmAll = Read-Input " ▶ 정말 '$($selected.AssetName)' 자산과 모든 계정을 완전히 삭제하시겠습니까? (Y/N)" -AllowEmpty $true
                        if ($confirmAll -match '^[Yy]$') {
                            $assets = @($assets | Where-Object { $_.AssetID -ne $selected.AssetID })
                            Save-Assets -Assets $assets
                            Write-Host "`n [v] 자산 및 하위 모든 계정이 완전히 삭제되었습니다." -ForegroundColor Green
                        } else {
                            Write-Host "`n [-] 삭제가 취소되었습니다." -ForegroundColor Yellow
                        }
                        $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                    } else {
                        Write-Host "`n [-] 삭제 작업이 취소되었습니다." -ForegroundColor Yellow
                        Start-Sleep -Seconds 1
                    }
                } else {
                    # 계정이 1개 이하인 경우 일반 전체 삭제 진행
                    Write-Host "`n [!] 삭제 대상: $($selected.AssetName) ($($selected.IP)) - 포함된 계정: $($selected.Accounts.Count)개" -ForegroundColor Yellow
                    $confirm = Read-Input " ▶ 해당 자산과 등록된 모든 계정을 완전히 삭제하시겠습니까? (Y/N)" -AllowEmpty $true
                    if ($confirm -match '^[Yy]$') {
                        $assets = @($assets | Where-Object { $_.AssetID -ne $selected.AssetID })
                        Save-Assets -Assets $assets
                        Write-Host "`n [v] 자산 및 하위 계정이 모두 삭제되었습니다." -ForegroundColor Green
                    } else {
                        Write-Host "`n [-] 삭제가 취소되었습니다." -ForegroundColor Yellow
                    }
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                }
            } catch {
                if ($_.Exception.Message -eq "CANCEL_ACTION") {
                    Write-Host "`n [-] 자산 삭제가 취소되어 메인 메뉴로 돌아갑니다." -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                } else { throw $_ }
            }
        }

        # ── 6. 마스터 비밀번호 변경 ──
        '6' {
            Change-MasterPasswordFlow
        }

        # ── 0. 프로그램 종료 ──
        '0' { 
            Write-Host "`n 프로그램을 종료합니다. 안전하게 닫힙니다." -ForegroundColor Cyan
            exit
        }

        default {
            if ($choice -ne '') {
                Write-Host " [!] 잘못된 입력입니다. 다시 선택해주세요." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}