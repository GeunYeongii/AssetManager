# AssetManager (보안 자산 관리자)

PowerShell 기반의 Zero-Knowledge(영지식) AES-256 군사 표준 암호화 로컬 자산 및 다중 계정 관리 도구입니다.

## 🚀 주요 기능
- **🛡️ AES-256 + PBKDF2 Zero-Knowledge 완전 암호화**:
  - 마스터 비밀번호로 실시간 키를 유도하여 모든 자산 및 계정 정보를 암호화 저장.
  - 비밀번호를 모르면 어떤 방법으로도 복호화 불가.
- **👥 단일 IP / 자산 내 다중 계정(계층형) 관리**:
  - 하나의 서버/IP에 대해 여러 계정(`root`, `admin`, `appuser`, `readonly` 등)을 개별 등록/수정/삭제 가능.
  - 계정별 권한 구분(역할), ID, PW, 개별 메모/설명 지원.
  - 비밀번호 숨김/보기(마스킹 토글) 지원.
- **🔍 통합 스마트 검색**:
  - IP, 자산명, 접속 URL뿐만 아니라 등록된 하위 계정의 ID, 역할, 설명까지 통합 검색 지원.
- **💻 직관적인 CLI UI**:
  - 한글/영문 너비 자동 정렬 콘솔 테이블.
  - 상세 조회 및 서브 계정 관리 워크플로우 제공.

## 📁 파일 구성
- `AssetManager.ps1`: AES-256 암호화 및 다중 계정 자산 관리 메인 스크립트
- `자산관리실행.bat`: 원클릭 실행 배치 파일
- `.gitignore`: 암호화된 자산 데이터(`SecureAssets.dat`) 등 개인정보 보호

## 💻 실행 방법
1. `자산관리실행.bat`을 더블 클릭하여 실행하거나
2. PowerShell에서 실행:
```powershell
powershell -ExecutionPolicy Bypass -File .\AssetManager.ps1
```
