# AssetManager (보안 자산 관리자)

PowerShell 기반의 Zero-Knowledge(영지식) AES-256 군사 표준 암호화 로컬 자산 및 CLI/GUI 다중 계정 관리 도구입니다.

## 🚀 주요 기능
- **🛡️ AES-256 + PBKDF2 Zero-Knowledge 완전 암호화**:
  - 마스터 비밀번호로 실시간 키를 유도하여 모든 자산 및 계정 정보를 암호화 저장.
  - 비밀번호를 모르면 어떤 방법으로도 복호화 불가.
- **🖥️ CLI vs GUI 계정 분리 관리**:
  - 하나의 서버/장비에 대해 **CLI(SSH/Telnet/콘솔)** 계정과 **GUI(웹콘솔/RDP/원격데스크톱)** 계정을 명확하게 분리 등록 및 관리.
  - CLI만 있는 서버, GUI만 있는 장비, 둘 다 있는 서버 모두 지원.
  - 조회 테이블 및 상세 화면에서 `[CLI]`, `[GUI]` 태그로 깔끔하게 구분 표시.
- **👀 비밀번호 상시 확인**:
  - 조회 및 상세 화면에서 비밀번호를 숨김 없이 평문으로 즉시 확인 가능.
- **⚡ 스마트 자산 추가 플로우 (IP 선입력 & 자동 매칭)**:
  - IP 선입력 후 기존 자산 매칭 시 접속 URL 등 기본 정보를 자동 유지한 채 서브 계정 추가 단계로 진입.
- **🚫 root 및 동일 계정 ID 중복 방지**:
  - 동일 접속 유형(CLI/GUI) 내에서 `root` 중복 추가 방지 및 서브 계정 역할 자동 부여.
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
