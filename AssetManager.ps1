# ==========================================
# PowerShell 보안 자산 관리자 (JSON + DPAPI + 마스터 비밀번호 인증)
# ==========================================

$DataFile = "$PSScriptRoot\SecureAssets.dat"
$AuthFile = "$PSScriptRoot\SecureAuth.dat"

# 1. 데이터 암호화 함수 (DPAPI)
function Protect-Data {
    param([string]$PlainText)
    $Secure = ConvertTo-SecureString -String $PlainText -AsPlainText -Force
    ConvertFrom-SecureString -SecureString $Secure
}

# 2. 데이터 복호화 함수 (DPAPI)
function Unprotect-Data {
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
    Write-Host -NoNewline "$PromptText: "
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

# 4. SHA-256 + Salt 해시 생성
function Get-PasswordHash {
    param([string]$Password, [string]$Salt)
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Password + $Salt)
    $hashBytes = $hasher.ComputeHash($bytes)
    return [System.Convert]::ToBase64String($hashBytes)
}

# 5. 마스터 비밀번호 저장 함수
function Set-MasterPassword {
    param([string]$NewPassword)
    $salt = [System.Guid]::NewGuid().ToString("N")
    $hash = Get-PasswordHash -Password $NewPassword -Salt $salt
    $authObj = @{
        Salt = $salt
        Hash = $hash
    }
    $authJson = ConvertTo-Json -InputObject $authObj -Compress
    $encryptedAuth = Protect-Data -PlainText $authJson
    [System.IO.File]::WriteAllText($AuthFile, $encryptedAuth, [System.Text.UTF8Encoding]::new($false))
}

# 6. 마스터 비밀번호 검증 및 초기 설정 절차
function Assert-MasterPassword {
    Clear-Host
    # 인증 파일이 없는 경우 -> 최초 설정
    if (-not (Test-Path $AuthFile)) {
        Show-Banner -Title "마스터 비밀번호 신규 설정" -Color "Yellow"
        Write-Host " [!] 최초 실행입니다. 프로그램 보호를 위한 마스터 비밀번호를 설정하세요.`n" -ForegroundColor Yellow
        
        while ($true) {
            $pwd1 = Read-MaskedInput -PromptText " ▶ 새 마스터 비밀번호 입력"
            if ([string]::IsNullOrWhiteSpace($pwd1)) {
                Write-Host " [!] 비밀번호는 공백일 수 없습니다.`n" -ForegroundColor Red
                continue
            }
            if ($pwd1.Length -lt 4) {
                Write-Host " [!] 비밀번호는 최소 4자리 이상이어야 합니다.`n" -ForegroundColor Red
                continue
            }
            
            $pwd2 = Read-MaskedInput -PromptText " ▶ 마스터 비밀번호 확인"
            if ($pwd1 -ne $pwd2) {
                Write-Host " [!] 비밀번호가 일치하지 않습니다. 다시 입력해주세요.`n" -ForegroundColor Red
                continue
            }
            
            Set-MasterPassword -NewPassword $pwd1
            Write-Host "`n [v] 마스터 비밀번호가 안전하게 설정되었습니다!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            break
        }
        return
    }

    # 인증 파일이 있는 경우 -> 비밀번호 검증
    try {
        $encryptedAuth = (Get-Content $AuthFile -Raw).Trim()
        $authJson = Unprotect-Data -EncryptedText $encryptedAuth
        $authObj = $authJson | ConvertFrom-Json
    } catch {
        Write-Host "`n [!] 인증 데이터 복호화 실패. 현재 Windows 계정과 일치하는지 확인하세요." -ForegroundColor Red
        $null = Read-Host "`n 아무 키나 누르면 종료됩니다..."
        exit
    }

    $maxAttempts = 5
    $attempts = 0

    while ($attempts -lt $maxAttempts) {
        Clear-Host
        Show-Banner -Title "보 안 인 증 (MASTER AUTH)" -Color "Cyan"
        Write-Host " 🔐 자산 관리자에 접근하려면 마스터 비밀번호를 입력해주세요.`n" -ForegroundColor White
        
        $inputPwd = Read-MaskedInput -PromptText " ▶ 마스터 비밀번호"
        
        if ([string]::IsNullOrEmpty($inputPwd)) {
            Write-Host " [!] 비밀번호를 입력해주세요." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            continue
        }

        $calcHash = Get-PasswordHash -Password $inputPwd -Salt $authObj.Salt
        if ($calcHash -eq $authObj.Hash) {
            Write-Host "`n [v] 인증에 성공하였습니다!" -ForegroundColor Green
            Start-Sleep -Milliseconds 600
            return
        } else {
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

# 7. 마스터 비밀번호 변경 함수
function Change-MasterPasswordFlow {
    try {
        Clear-Host
        Show-Banner -Title "마스터 비밀번호 변경" -Color "Magenta"
        Write-Host " [*] 변경을 취소하려면 언제든 창을 닫거나 ESC/빈칸으로 진행하세요.`n" -ForegroundColor Gray

        $encryptedAuth = (Get-Content $AuthFile -Raw).Trim()
        $authJson = Unprotect-Data -EncryptedText $encryptedAuth
        $authObj = $authJson | ConvertFrom-Json

        $currPwd = Read-MaskedInput -PromptText " ▶ 현재 마스터 비밀번호"
        $calcHash = Get-PasswordHash -Password $currPwd -Salt $authObj.Salt
        if ($calcHash -ne $authObj.Hash) {
            Write-Host "`n [!] 현재 비밀번호가 일치하지 않습니다." -ForegroundColor Red
            $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
            return
        }

        $newPwd1 = Read-MaskedInput -PromptText "`n ▶ 변경할 새 마스터 비밀번호"
        if ([string]::IsNullOrWhiteSpace($newPwd1) -or $newPwd1.Length -lt 4) {
            Write-Host "`n [!] 새 비밀번호는 최소 4자리 이상이어야 합니다." -ForegroundColor Red
            $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
            return
        }

        $newPwd2 = Read-MaskedInput -PromptText " ▶ 변경할 새 마스터 비밀번호 확인"
        if ($newPwd1 -ne $newPwd2) {
            Write-Host "`n [!] 새 비밀번호가 일치하지 않습니다." -ForegroundColor Red
            $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
            return
        }

        Set-MasterPassword -NewPassword $newPwd1
        Write-Host "`n [v] 마스터 비밀번호가 성공적으로 변경되었습니다!" -ForegroundColor Green
        $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
    } catch {
        Write-Host "`n [!] 비밀번호 변경 중 오류가 발생했습니다: $($_.Exception.Message)" -ForegroundColor Red
        $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
    }
}

# 8. 자산 불러오기
function Get-Assets {
    if (-not (Test-Path $DataFile)) { return @() }
    try {
        $EncryptedText = (Get-Content $DataFile -Raw).Trim()
        if ([string]::IsNullOrWhiteSpace($EncryptedText)) { return @() }
        $PlainText = Unprotect-Data -EncryptedText $EncryptedText
        $result = $PlainText | ConvertFrom-Json
        if ($result -isnot [array]) {
            return @($result)
        }
        return $result
    } catch {
        Write-Warning "데이터 복호화 실패. 파일 생성 계정과 일치하는지 확인하세요."
        return @()
    }
}

# 9. 자산 저장하기
function Save-Assets {
    param([array]$Assets)
    if ($Assets.Count -eq 0) {
        $JsonText = '[]'
    } else {
        $JsonText = ConvertTo-Json -InputObject @($Assets) -Depth 3 -Compress
    }
    $EncryptedText = Protect-Data -PlainText $JsonText
    [System.IO.File]::WriteAllText($DataFile, $EncryptedText, [System.Text.UTF8Encoding]::new($false))
}

# 10. 자산 검색 공통 함수
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
            $_.AssetName -like "*$Keyword*" -or
            $_.Note -like "*$Keyword*" -or
            $_.ID -like "*$Keyword*" -or
            $_.PW -like "*$Keyword*"
        }
        Write-Host "`n [*] 텍스트 검색 모드로 동작합니다. (검색어: '$Keyword')" -ForegroundColor Cyan
    }
    return @($results)
}

# 11. 한글 및 영문 너비 계산용 유틸리티
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

# 12. 검색 결과를 표로 깔끔하게 출력
function Show-NumberedResults {
    param([array]$Results)
    
    $hNo   = Pad-RightDisplay "번호" 6
    $hName = Pad-RightDisplay "자산명" 18
    $hIP   = Pad-RightDisplay "IP주소" 18
    $hID   = Pad-RightDisplay "계정ID" 16
    $hPW   = Pad-RightDisplay "패스워드" 16
    $hURL  = Pad-RightDisplay "접속URL" 28
    $hNote = Pad-RightDisplay "비고" 18
    
    Write-Host " $hNo $hName $hIP $hID $hPW $hURL $hNote" -ForegroundColor DarkGray
    Write-Host " ────   ────────────────  ────────────────  ──────────────  ──────────────  ──────────────────────────  ────────────────" -ForegroundColor DarkGray
    
    for ($i = 0; $i -lt $Results.Count; $i++) {
        $r = $Results[$i]
        $noStr = ($i + 1).ToString()
        
        $cNo   = Pad-RightDisplay $noStr 6
        $cName = Pad-RightDisplay $r.AssetName 18
        $cIP   = Pad-RightDisplay $r.IP 18
        $cID   = Pad-RightDisplay $r.ID 16
        $cPW   = Pad-RightDisplay $r.PW 16
        $cURL  = Pad-RightDisplay $r.WebURL 28
        $cNote = Pad-RightDisplay $r.Note 18
        
        Write-Host " $cNo $cName $cIP $cID $cPW $cURL $cNote" -ForegroundColor White
    }
}

# 13. UI 공통 함수: 상단 배너 출력
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

# 14. 사용자 입력 및 취소(q/엔터) 처리 래퍼 함수
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

# ──────────────────────────────────────────
# 실행 시 마스터 비밀번호 인증 수행
# ──────────────────────────────────────────
Assert-MasterPassword

# 15. 메인 메뉴 루프
while ($true) {
    Clear-Host
    Show-Banner -Title "SECURE ASSET MANAGER v1.1" -Color "Cyan"
    
    Write-Host "   [1] 자산 검색                 [2] 자산 조회 (전체)" -ForegroundColor White
    Write-Host "   [3] 자산 추가                 [4] 자산 수정" -ForegroundColor White
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
                Write-Host " [*] 빈칸 상태로 Enter를 누르거나 'q'를 입력하면 메뉴로 돌아갑니다.`n" -ForegroundColor Gray
                
                if ($assets.Count -eq 0) {
                    Write-Host " [!] 등록된 자산이 없습니다." -ForegroundColor Yellow
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                    break
                }
                
                $keyword = Read-Input " ▶ 검색어를 입력하세요"
                
                $results = @(Search-Assets -AllAssets $assets -Keyword $keyword)
                if ($results.Count -eq 0) {
                    Write-Host " [!] 검색 결과가 없습니다." -ForegroundColor Yellow
                } else {
                    Write-Host "`n [ 검색 결과 ]" -ForegroundColor Green
                    Show-NumberedResults -Results $results
                    Write-Host "`n 총 검색된 자산: $($results.Count) 건" -ForegroundColor Gray
                }
                $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
            } catch {
                if ($_.Exception.Message -eq "CANCEL_ACTION") {
                    Write-Host "`n [-] 작업이 취소되어 메인 메뉴로 돌아갑니다." -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                } else { throw $_ }
            }
        }

        # ── 2. 자산 조회 (전체) ──
        '2' { 
            Clear-Host
            Show-Banner -Title "전체 자산 목록" -Color "Green"
            
            if ($assets.Count -eq 0) {
                Write-Host " [!] 등록된 자산이 없습니다." -ForegroundColor Yellow
            } else {
                Show-NumberedResults -Results $assets
                Write-Host "`n 총 자산 수: $($assets.Count) 건" -ForegroundColor Gray
            }
            $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
        }

        # ── 3. 자산 추가 ──
        '3' { 
            try {
                Clear-Host
                Show-Banner -Title "새 자산 추가" -Color "Yellow"
                Write-Host " [*] 중간에 취소하려면 언제든 'q'를 입력하거나 빈칸 상태에서 Enter를 누르세요.`n" -ForegroundColor Gray
                
                $inputName = Read-Input " ▶ 1. 자산 이름"
                $inputIP   = Read-Input " ▶ 2. IP 주소"

                # IP 중복 체크
                $duplicate = $assets | Where-Object { $_.IP -eq $inputIP }
                if ($duplicate) {
                    Write-Host "`n [!] 이미 동일한 IP를 가진 자산이 존재합니다." -ForegroundColor Red
                    Write-Host " ──────────────────────────────────────────" -ForegroundColor Red
                    Show-NumberedResults -Results @($duplicate)
                    Write-Host " [!] 자산 추가가 중단되었습니다." -ForegroundColor Yellow
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                    break
                }

                $newAsset = [PSCustomObject]@{
                    AssetID   = [guid]::NewGuid().ToString()
                    AssetName = $inputName
                    IP        = $inputIP
                    ID        = Read-Input " ▶ 3. 계정 ID"
                    PW        = Read-Input " ▶ 4. 계정 PW"
                    WebURL    = Read-Input " ▶ 5. 접속 URL (포트 포함)"
                    Note      = Read-Input " ▶ 6. 비고"
                }
                $assets += $newAsset
                Save-Assets -Assets $assets
                Write-Host "`n [v] 자산이 성공적으로 추가되었습니다." -ForegroundColor Green
                $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
            } catch {
                if ($_.Exception.Message -eq "CANCEL_ACTION") {
                    Write-Host "`n [-] 자산 추가가 취소되어 메인 메뉴로 돌아갑니다." -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                } else { throw $_ }
            }
        }

        # ── 4. 자산 수정 ──
        '4' { 
            try {
                Clear-Host
                Show-Banner -Title "자 산 수 정" -Color "Magenta"
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
                Show-NumberedResults -Results $results
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

                Write-Host "`n [*] 새로운 값을 입력하세요. (기존 유지 시 Enter, 수정 완전 취소 시 q 입력)" -ForegroundColor Cyan

                $newName = Read-Input " ▶ 1. 자산 이름 [$($assets[$origIdx].AssetName)]" -IsEditMode $true
                if ($newName) { $assets[$origIdx].AssetName = $newName }

                $newIP = Read-Input " ▶ 2. IP 주소 [$($assets[$origIdx].IP)]" -IsEditMode $true
                if ($newIP) { $assets[$origIdx].IP = $newIP }

                $newID = Read-Input " ▶ 3. 계정 ID [$($assets[$origIdx].ID)]" -IsEditMode $true
                if ($newID) { $assets[$origIdx].ID = $newID }

                $newPW = Read-Input " ▶ 4. 계정 PW [********]" -IsEditMode $true
                if ($newPW) { $assets[$origIdx].PW = $newPW }

                $newURL = Read-Input " ▶ 5. 접속 URL [$($assets[$origIdx].WebURL)]" -IsEditMode $true
                if ($newURL) { $assets[$origIdx].WebURL = $newURL }

                $newNote = Read-Input " ▶ 6. 비고 [$($assets[$origIdx].Note)]" -IsEditMode $true
                if ($newNote) { $assets[$origIdx].Note = $newNote }

                Save-Assets -Assets $assets
                Write-Host "`n [v] 자산 정보가 수정되었습니다." -ForegroundColor Green
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
                Write-Host " [*] 검색 및 대상 선택 중 빈칸 Enter 또는 'q'를 입력하면 취소됩니다.`n" -ForegroundColor Gray
                
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
                Show-NumberedResults -Results $results
                Write-Host ""

                $selNum = Read-Input " ▶ 삭제할 자산의 번호를 입력하세요"
                $selIdx = [int]$selNum - 1
                if ($selIdx -lt 0 -or $selIdx -ge $results.Count) {
                    Write-Host " [!] 잘못된 번호입니다." -ForegroundColor Red
                    $null = Read-Host "`n ▶ 계속하려면 Enter를 누르세요..."
                    break
                }

                $selected = $results[$selIdx]
                Write-Host "`n [!] 삭제 대상: $($selected.AssetName) ($($selected.IP))" -ForegroundColor Yellow
                $confirm = Read-Input " ▶ 정말 삭제하시겠습니까? (Y/N)" -AllowEmpty $true
                if ($confirm -match '^[Yy]$') {
                    $assets = $assets | Where-Object { $_.AssetID -ne $selected.AssetID }
                    Save-Assets -Assets @($assets)
                    Write-Host "`n [v] 자산이 삭제되었습니다." -ForegroundColor Green
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