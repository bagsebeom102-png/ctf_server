# DH CTF

고등학교/동아리용 간단한 CTF 플랫폼입니다.

## 기능
- 회원가입 / 로그인
- 기본 관리자 계정
- 시스템 해킹 / 리버싱 / 웹 해킹 / 암호학 각 2문제
- 플래그 제출 및 풀이 기록
- 관리자 페이지에서 사용자별 풀이 현황 확인
- 쿠키 변조 실습
- SQL Injection 실습 (별도의 샌드박스 DB만 사용)

## 실행

```bash
python -m venv venv
```

Windows:
```bash
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Linux/macOS:
```bash
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

브라우저:
http://127.0.0.1:5000

## 기본 관리자
- ID: admin
- PW: admin1234

공개 서버에 올리기 전에 반드시 환경변수로 바꾸세요.

Linux/macOS:
```bash
export ADMIN_PASSWORD='강한비밀번호'
export SECRET_KEY='아주긴랜덤문자열'
python app.py
```

Windows PowerShell:
```powershell
$env:ADMIN_PASSWORD="강한비밀번호"
$env:SECRET_KEY="아주긴랜덤문자열"
python app.py
```

## 주의
시스템 해킹 문제는 실제 운영체제 권한 상승 취약점을 만들지 않습니다.
웹 SQLi 문제도 별도의 challenge_sqli.db만 사용하여 메인 회원 DB와 분리했습니다.
