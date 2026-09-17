# AssetManager (보안 자산 관리자)

PowerShell 기반의 Zero-Knowledge(영지식) AES-256 군사 표준 암호화 로컬 자산 및 CLI/GUI 다중 계정 관리 도구입니다.

## 🚀 주요 기능
- **🛡️ AES-256 + PBKDF2 Zero-Knowledge 완전 암호화**:
  - 마스터 비밀번호로 실시간 키를 유도하여 모든 자산 및 계정 정보를 암호화 저장.
  - 비밀번호를 모르면 어떤 방법으로도 복호화 불가.
- **🖥️ CLI(SSH/Telnet/Console/RDP) vs GUI(웹콘솔) 계정 분리 관리**:
  - `CLI (SSH/Telnet/Console/RDP)`: 원격 접속 및 콘솔 계정 통합 관리.
  - `GUI (웹콘솔)`: 관리 웹 UI 및 웹페이지 계정 관리.
- **👑 단일 고유 root(관리자) 역할 규칙**:
  - 한 자산(서버) 내에서 `root` 역할은 오직 1개만 허용 (윈도우 `administrator`도 역할은 `root`로 통일).
  - 이미 관리자(root)가 존재하는 자산에는 자동으로 서브 계정이 '일반' 역할로 배정됨.
- **⚡ 전용 root 수정 모드**:
  - 관리자(root) 계정 수정 시 불필요한 ID/역할 질문 없이 **패스워드 및 메모만 즉시 수정**.
- **🔒 패스워드 입력 시 `*` 마스킹 & 조회 시 평문 상시 확인**:
  - 등록/수정 입력 시에는 `*` 마스킹 처리, 조회 화면에서는 평문으로 직관적 확인.
- **⚡ 스마트 자산 추가 플로우 (IP 선입력 & 자동 매칭)**:
  - IP 선입력 후 기존 자산 매칭 시 접속 URL 등 기본 정보를 자동 유지한 채 서브 계정 추가 단계로 진입.
- **🔍 통합 스마트 검색**:
  - IP, 자산명, 접속 URL뿐만 아니라 CLI/GUI 접근 유형, 계정 ID, 역할, 메모까지 통합 검색 지원.

## 📁 파일 구성
- `AssetManager.ps1`: AES-256 암호화 및 CLI/GUI 다중 계정 자산 관리 메인 스크립트
- `자산관리실행.bat`: 원클릭 실행 배치 파일
- `.gitignore`: 암호화된 자산 데이터(`SecureAssets.dat`) 등 개인정보 보호

## 💻 실행 방법
1. `자산관리실행.bat`을 더블 클릭하여 실행하거나
2. PowerShell에서 실행:
```powershell
powershell -ExecutionPolicy Bypass -File .\AssetManager.ps1
```
