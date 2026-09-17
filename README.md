# AssetManager (보안 자산 관리자)

PowerShell 기반의 로컬 자산 및 서버/계정 정보 관리 도구입니다.

## 🚀 주요 기능
- **🔐 마스터 비밀번호 보안 인증**:
  - 최초 실행 시 마스터 비밀번호 설정(4자리 이상, `*` 마스킹 지원).
  - SHA-256 + Salt 해싱 및 Windows DPAPI 복합 암호화 적용.
  - 실행 시 5회 연속 인증 실패 시 자동 강제 종료.
  - 메인 메뉴에서 언제든 마스터 비밀번호 변경 지원.
- **암호화 저장 (Windows DPAPI)**: 로컬 사용자 계정 키 기반의 안전한 암호화를 통해 자산 데이터(`SecureAssets.dat`)를 보관합니다.
- **자산 검색**: 자산명, IP, ID, URL, 비고 등 다양한 키워드 및 IP/URL 검색 지원.
- **전체 자산 조회**: 등록된 모든 자산을 콘솔 테이블 형식으로 깔끔하게 출력.
- **자산 등록/수정/삭제**: 중복 IP 방지 및 간편한 CLI 입력/수정/삭제 워크플로우 제공.
- **직관적인 CLI UI**: 너비 정렬, 상단 배너, 직관적인 컬러 하이라이팅 제공.

## 📁 파일 구성
- `AssetManager.ps1`: 메인 자산 관리 PowerShell 스크립트 (인증 및 데이터 관리)
- `자산관리실행.bat`: PowerShell 실행 정책(Bypass)을 적용하여 원클릭으로 실행하는 배치 파일
- `.gitignore`: 암호화 인증/자산 데이터(`SecureAssets.dat`, `SecureAuth.dat`) 등 민감 정보 유출 방지

## 💻 실행 방법
1. `자산관리실행.bat`을 더블 클릭하거나
2. PowerShell 터미널에서 다음 명령어 실행:
```powershell
powershell -ExecutionPolicy Bypass -File .\AssetManager.ps1
```
