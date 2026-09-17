# ==============================================================================
# PowerShell 완전 보안 자산 관리자 (AES-256 + 다중 계정 계층형 관리)
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
    param([string]$PromptText = " ▶ 비밀번호를 입력하세요")
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
            return ""
        } elseif ([char]::IsControl($key.KeyChar)) {
            continue
        } else {
            $pwd += $key.KeyChar
            Write-Host -NoNewline "*"
        }
    }
    return $pwd
}

# 4. 데이터 정규화 함수 (단일 계정 -> 다중 계정 배열 호환)
function Normalize-Asset {
    param($raw)
    $accList = @()
    if ($raw.PSObject.Properties['Accounts'] -and $raw.Accounts) {
        if ($raw.Accounts -is [array]) {
            $accList = @($raw.Accounts)
        } else {
            $accList = @($raw.Accounts)
        }
    } elseif ($raw.PSObject.Properties['ID'] -or $raw.PSObject.Properties['PW']) {
        if ($raw.ID -or $raw.PW) {
            $accList += [PSCustomObject]@{
                AccountID   = [guid]::NewGuid().ToString()
                AccountType = "기본"
                ID          = [string]$raw.ID
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

# 7. 한글 및 영문 너비 계산용 유틸리티
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

# 8. UI 공통 배너
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

# 9. 사용자 입력 처리
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

# 10. 프로그램 시작: 마스터 비밀번호 인증 및 세션 활성화
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

# 11. 마스터 비밀번호 변경
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

# 12. 전체/검색 자산 요약 목록 출력 함수
function Show-AssetSummaryTable {
    param([array]$AssetList)

    $hNo    = Pad-RightDisplay "번호" 6
    $hName  = Pad-RightDisplay "자산명" 18
    $hIP    = Pad-RightDisplay "IP주소" 18
    $hAccs  = Pad-RightDisplay "등록계정(수)" 20
    $hURL   = Pad-RightDisplay "접속URL" 24
    $hNote  = Pad-RightDisplay "비고" 18

    Write-Host " $hNo $hName $hIP $hAccs $hURL $hNote" -ForegroundColor DarkGray
    Write-Host " ────   ────────────────  ────────────────  ──────────────────  ──────────────────────  ────────────────" -ForegroundColor DarkGray

    for ($i = 0; $i -lt $AssetList.Count; $i++) {
        $a = $AssetList[$i]
        $noStr = ($i + 1).ToString()

        # 등록 계정 요약 텍스트
        $accCount = if ($a.Accounts) { $a.Accounts.Count } else { 0 }
        $accSummary = "계정 없음 (0)"
        if ($accCount -eq 1) {
            $first = $a.Accounts[0]
            $typeStr = if ($first.AccountType) { "[$($first.AccountType)] " } else { "" }
            $accSummary = "$typeStr$($first.ID)"
        } elseif ($accCount -gt 1) {
            $first = $a.Accounts[0]
            $typeStr = if ($first.AccountType) { "[$($first.AccountType)] " } else { "" }
            $accSummary = "$typeStr$($first.ID) 외 $($accCount - 1)개"
        }

        $cNo   = Pad-RightDisplay $noStr 6
        $cName = Pad-RightDisplay $a.AssetName 18
        $cIP   = Pad-RightDisplay $a.IP 18
        $cAccs = Pad-RightDisplay $accSummary 20
        $cURL  = Pad-RightDisplay $a.WebURL 24
        $cNote = Pad-RightDisplay $a.Note 18

        Write-Host " $cNo $cName $cIP $cAccs $cURL $cNote" -ForegroundColor White
    }
}

# 13. 자산 검색 (다중 계정 ID/타입/설명까지 검색)
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
                    if ($acc.ID -like "*$Keyword*" -or $acc.AccountType -like "*$Keyword*" -or $acc.Description -like "*$Keyword*" -or $acc.PW -like "*$Keyword*") {
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

# 14. 자산 상세 정보 및 하위 계정 관리 화면
function Show-AssetDetailManage {
    param([string]$AssetID)

    $showPasswords = $false

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

        if ($accList.Count -eq 0) {
            Write-Host "   (등록된 계정이 없습니다. [1]번을 눌러 새 계정을 추가하세요.)" -ForegroundColor Gray
        } else {
            $hNo    = Pad-RightDisplay "번호" 6
            $hType  = Pad-RightDisplay "구분/역할" 14
            $hID    = Pad-RightDisplay "계정 ID" 16
            $hPW    = Pad-RightDisplay "패스워드" 18
            $hDesc  = Pad-RightDisplay "계정 설명/메모" 20

            Write-Host "  $hNo $hType $hID $hPW $hDesc" -ForegroundColor DarkGray
            Write-Host "  ────   ────────────  ──────────────  ────────────────  ────────────────────" -ForegroundColor DarkGray

            for ($i = 0; $i -lt $accList.Count; $i++) {
                $acc = $accList[$i]
                $noStr = ($i + 1).ToString()
                $typeStr = if ($acc.AccountType) { "[$($acc.AccountType)]" } else { "[-]" }
                $pwStr = if ($showPasswords) { $acc.PW } else { "********" }

                $cNo   = Pad-RightDisplay $noStr 6
                $cType = Pad-RightDisplay $typeStr 14
                $cID   = Pad-RightDisplay $acc.ID 16
                $cPW   = Pad-RightDisplay $pwStr 18
                $cDesc = Pad-RightDisplay $acc.Description 20

                Write-Host "  $cNo $cType $cID $cPW $cDesc" -ForegroundColor White
            }
        }

        Write-Host "`n ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        $pwToggleLabel = if ($showPasswords) { "비밀번호 가리기 (숨김)" } else { "비밀번호 보기 (표시)" }
        Write-Host "   [1] 새 계정 추가              [2] 계정 수정" -ForegroundColor White
        Write-Host "   [3] 계정 삭제                 [4] $pwToggleLabel" -ForegroundColor White
        Write-Host "   [0] 이전 화면으로 돌아가기" -ForegroundColor DarkGray
        Write-Host " ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

        while ([Console]::KeyAvailable) { [Console]::ReadKey($true) | Out-Null }
        Write-Host ""
        $action = (Read-Host " ▶ 작업을 선택하세요").Trim()

        switch ($action) {
            # ── 1. 계정 추가 ──
            '1' {
                try {
                    Write-Host "`n [ 새 계정 추가 ] ('q' 입력 시 취소)" -ForegroundColor Cyan
                    $inType = Read-Input " ▶ 계정 구분/역할 (예: root, admin, webuser, dev 등)"
                    $inID   = Read-Input " ▶ 계정 ID"
                    $inPW   = Read-Input " ▶ 패스워드"
                    $inDesc = Read-Input " ▶ 계정 설명/메모" -AllowEmpty $true

                    $newAcc = [PSCustomObject]@{
                        AccountID   = [guid]::NewGuid().ToString()
                        AccountType = $inType
                        ID          = $inID
                        PW          = $inPW
                        Description = $inDesc
                    }

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
                    Write-Host "`n [*] 수정할 값을 입력하세요. (기존 유지 시 Enter, 취소 시 q)" -ForegroundColor Cyan
                    $uType = Read-Input " ▶ 계정 구분 [$($targetAcc.AccountType)]" -IsEditMode $true
                    $uID   = Read-Input " ▶ 계정 ID [$($targetAcc.ID)]" -IsEditMode $true
                    $uPW   = Read-Input " ▶ 패스워드 [********]" -IsEditMode $true
                    $uDesc = Read-Input " ▶ 계정 설명 [$($targetAcc.Description)]" -IsEditMode $true

                    for ($i = 0; $i -lt $allAssets.Count; $i++) {
                        if ($allAssets[$i].AssetID -eq $AssetID) {
                            for ($j = 0; $j -lt $allAssets[$i].Accounts.Count; $j++) {
                                if ($allAssets[$i].Accounts[$j].AccountID -eq $targetAcc.AccountID) {
                                    if ($uType) { $allAssets[$i].Accounts[$j].AccountType = $uType }
                                    if ($uID)   { $allAssets[$i].Accounts[$j].ID = $uID }
                                    if ($uPW)   { $allAssets[$i].Accounts[$j].PW = $uPW }
                                    if ($uDesc) { $allAssets[$i].Accounts[$j].Description = $uDesc }
                                    break
                                }
                            }
                            break
                        }
                    }
                    Save-Assets -Assets $allAssets
                    Write-Host "`n [v] 계정 정보가 수정되었습니다." -ForegroundColor Green
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
                    $confirm = Read-Input " ▶ '[$($targetAcc.AccountType)] $($targetAcc.ID)' 계정을 삭제하시겠습니까? (Y/N)" -AllowEmpty $true
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

            # ── 4. 비밀번호 토글 ──
            '4' {
                $showPasswords = -not $showPasswords
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
# 15. 프로그램 시작: 세션 인증
# ─────────────────────────────────────────────────────────────
Initialize-SessionAuth

# 16. 메인 메뉴 루프
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

        # ── 3. 새 자산 추가 ──
        '3' { 
            try {
                Clear-Host
                Show-Banner -Title "새 자산 추가" -Color "Yellow"
                Write-Host " [*] 취소하려면 언제든 'q'를 입력하거나 빈칸에서 Enter를 누르세요.`n" -ForegroundColor Gray
                
                $inputName = Read-Input " ▶ 1. 자산 이름 (예: 운영 DB서버, 웹서버01 등)"
                $inputIP   = Read-Input " ▶ 2. IP 주소"

                # IP가 이미 있는 경우 알림 (다중 등록 허용 여부 안내)
                $duplicate = $assets | Where-Object { $_.IP -eq $inputIP }
                if ($duplicate) {
                    Write-Host "`n [!] 알림: 동일한 IP($inputIP)를 사용하는 자산이 이미 존재합니다: '$($duplicate.AssetName)'" -ForegroundColor Yellow
                    $proceed = Read-Input " ▶ 그래도 별도 자산으로 추가하시겠습니까? (Y/N)" -AllowEmpty $true
                    if ($proceed -notmatch '^[Yy]$') {
                        Write-Host " [!] 자산 추가가 취소되었습니다. 기존 자산에 계정을 추가하려면 [2]번 조회를 이용하세요." -ForegroundColor Yellow
                        $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                        break
                    }
                }

                $inputURL  = Read-Input " ▶ 3. 접속 URL (포트 포함, 없을 시 Enter)" -AllowEmpty $true
                $inputNote = Read-Input " ▶ 4. 비고 / 메모 (없을 시 Enter)" -AllowEmpty $true

                # 첫 번째 계정 등록
                Write-Host "`n [ 첫 번째 계정 정보 등록 ]" -ForegroundColor Cyan
                $accType = Read-Input " ▶ 5. 계정 구분/역할 (예: root, admin, user 등)"
                $accID   = Read-Input " ▶ 6. 계정 ID"
                $accPW   = Read-Input " ▶ 7. 패스워드"
                $accDesc = Read-Input " ▶ 8. 계정 설명 (선택, 없을 시 Enter)" -AllowEmpty $true

                $newAccounts = @(
                    [PSCustomObject]@{
                        AccountID   = [guid]::NewGuid().ToString()
                        AccountType = $accType
                        ID          = $accID
                        PW          = $accPW
                        Description = $accDesc
                    }
                )

                # 추가 계정 연속 등록 여부
                while ($true) {
                    Write-Host ""
                    $more = Read-Input " ▶ 이 자산에 계정을 더 추가하시겠습니까? (Y/N)" -AllowEmpty $true
                    if ($more -match '^[Yy]$') {
                        Write-Host "`n [ 추가 계정 등록 ]" -ForegroundColor Cyan
                        $mType = Read-Input " ▶ 계정 구분/역할 (예: admin, devuser 등)"
                        $mID   = Read-Input " ▶ 계정 ID"
                        $mPW   = Read-Input " ▶ 패스워드"
                        $mDesc = Read-Input " ▶ 계정 설명 (선택)" -AllowEmpty $true
                        $newAccounts += [PSCustomObject]@{
                            AccountID   = [guid]::NewGuid().ToString()
                            AccountType = $mType
                            ID          = $mID
                            PW          = $mPW
                            Description = $mDesc
                        }
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
                Write-Host "`n [v] 자산 및 계정 $($newAccounts.Count)개가 성공적으로 등록되었습니다!" -ForegroundColor Green
                $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
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

                $newNote = Read-Input " ▶ 4. 비고 [$($assets[$origIdx].Note)]" -IsEditMode $true
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

        # ── 5. 자산 삭제 ──
        '5' { 
            try {
                Clear-Host
                Show-Banner -Title "자 산 삭 제" -Color "Red"
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

                $selNum = Read-Input " ▶ 삭제할 자산의 번호를 입력하세요"
                $selIdx = [int]$selNum - 1
                if ($selIdx -lt 0 -or $selIdx -ge $results.Count) {
                    Write-Host " [!] 잘못된 번호입니다." -ForegroundColor Red
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                    break
                }

                $selected = $results[$selIdx]
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