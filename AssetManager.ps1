# ==========================================
# PowerShell 보안 자산 관리자 (JSON + DPAPI)
# ==========================================

$DataFile = "$PSScriptRoot\SecureAssets.dat"

# 1. 데이터 암호화 함수
function Protect-Data {
    param([string]$PlainText)
    $Secure = ConvertTo-SecureString -String $PlainText -AsPlainText -Force
    ConvertFrom-SecureString -SecureString $Secure
}

# 2. 데이터 복호화 함수
function Unprotect-Data {
    param([string]$EncryptedText)
    $Secure = ConvertTo-SecureString -String $EncryptedText
    $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
    $PlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($Ptr)
    return $PlainText
}

# 3. 자산 불러오기
function Get-Assets {
    if (-not (Test-Path $DataFile)) { return @() }
    try {
        $EncryptedText = (Get-Content $DataFile -Raw).Trim()
        if ([string]::IsNullOrWhiteSpace($EncryptedText)) { return @() }
        $PlainText = Unprotect-Data -EncryptedText $EncryptedText
        $result = $PlainText | ConvertFrom-Json
        # 항상 배열로 반환 (단일 객체일 경우 배열로 감싸기)
        if ($result -isnot [array]) {
            return @($result)
        }
        return $result
    } catch {
        Write-Warning "데이터 복호화 실패. 파일 생성 계정과 일치하는지 확인하세요."
        return @()
    }
}

# 4. 자산 저장하기
function Save-Assets {
    param([array]$Assets)
    # 빈 배열이면 빈 JSON 배열로, 아니면 항상 배열 형태로 직렬화
    if ($Assets.Count -eq 0) {
        $JsonText = '[]'
    } else {
        $JsonText = ConvertTo-Json -InputObject @($Assets) -Depth 3 -Compress
    }
    $EncryptedText = Protect-Data -PlainText $JsonText
    [System.IO.File]::WriteAllText($DataFile, $EncryptedText, [System.Text.UTF8Encoding]::new($false))
}

# 5. 자산 검색 공통 함수
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

# 6. 한글 및 영문 너비 계산용 유틸리티
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

# 7. 검색 결과를 표로 깔끔하게 출력 (정확한 칸 맞춤)
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

# 8. UI 공통 함수: 상단 배너 출력
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

# 9. 사용자 입력 및 취소(q/엔터) 처리 래퍼 함수
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

# 10. 메인 메뉴 루프
while ($true) {
    Clear-Host
    Show-Banner -Title "SECURE ASSET MANAGER v1.0" -Color "Cyan"
    
    Write-Host "   [1] 자산 검색                 [2] 자산 조회 (전체)" -ForegroundColor White
    Write-Host "   [3] 자산 추가                 [4] 자산 수정" -ForegroundColor White
    Write-Host "   [5] 자산 삭제                 [0] 프로그램 종료" -ForegroundColor DarkGray
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