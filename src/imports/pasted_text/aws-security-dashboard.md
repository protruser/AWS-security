AWS 클라우드 기반 보안 모니터링 및 자동 조치 대시보드를 디자인해 주세요.

## 프로젝트 목적

AWS에서 운영되는 쇼핑몰 서비스를 대상으로 보안 이벤트를 실시간 탐지하고, 탐지 위치와 영향받은 자산을 아키텍처 맵에서 시각화하는 보안관제 대시보드입니다.

사용자는 보안 이벤트가 발생한 자산을 클릭해 관련 로그와 공격 경로를 확인하고, 필요한 경우 관리자 승인을 거쳐 자동 보안 조치를 실행할 수 있어야 합니다.

## 화면 콘셉트

전체 화면을 다음 비율로 구성해 주세요.

* 왼쪽 약 2/3: 실시간 AWS 아키텍처 관제 맵
* 오른쪽 약 1/3: 조치 필요 목록 및 이벤트 상세 패널

보안관제 담당자가 장시간 화면을 띄워놓고 사용하는 시스템이므로 정보 밀도는 높게 유지하되, 지나치게 화려하거나 피로한 디자인은 피해주세요.

## 디자인 스타일

* 흰색 또는 매우 연한 Blue Gray 배경
* Navy, Deep Blue, Sky Blue 중심
* 정상 상태는 Blue 또는 Green
* 주의 상태는 Yellow 또는 Orange
* 위험 상태는 Red
* 카드에는 얇은 Blue Gray 테두리와 약한 그림자 적용
* 반경 8~12px의 정돈된 카드
* Pretendard 또는 Noto Sans KR 사용
* 국내 대기업 IT 운영 시스템처럼 안정적이고 전문적인 분위기
* 특정 기업 로고나 디자인을 그대로 복제하지 않음
* 검은 배경, 과도한 네온, 사이버펑크 효과 사용 금지
* Desktop 1600×900 기준
* 모든 화면 텍스트는 한국어 사용

## 상단 헤더

상단 고정 헤더를 구성해 주세요.

* 서비스명: AWS Security Monitoring Center
* 현재 메뉴: 통합 보안관제
* 시스템 상태: 정상 운영 중
* LIVE 표시
* 자동 갱신 주기: 5초
* 마지막 갱신 시각
* Critical 알림 개수
* 알림 아이콘
* 관리자 프로필

LIVE 상태는 작은 청록색 점과 약한 Pulse 애니메이션으로 표현해 주세요.

## 왼쪽 영역: 인터랙티브 AWS 아키텍처 관제 맵

첨부된 AWS 아키텍처를 관제 화면에 맞게 단순화하여 표현해 주세요. 원본 구성도를 그대로 축소하지 말고, 실제 보안 이벤트의 위치와 이동 경로를 빠르게 파악할 수 있도록 핵심 자산 위주로 구성합니다.

### 1. 외부 접근 주체

아키텍처 왼쪽에 다음 주체를 배치해 주세요.

* 일반 사용자
* 공격자 서버
* 보안 관리자

트래픽 색상은 다음과 같이 구분합니다.

* 정상 사용자 트래픽: Blue
* 관리자 트래픽: Green
* 공격 트래픽: Red 점선
* 자동 조치 흐름: Red 실선
* 관리 및 자격증명 흐름: Green
* 보안 탐지 결과 흐름: Purple 또는 Dark Blue

### 2. 퍼블릭 진입 영역

일반 사용자와 공격자 경로:

일반 사용자 또는 공격자 서버
→ 쇼핑몰용 AWS WAF
→ 쇼핑몰용 ALB
→ K3s nginx

쇼핑몰용 WAF 카드에는 다음 항목을 표시합니다.

* SQL Injection
* XSS
* Rate Limiting
* 무차별 로그인 탐지
* 차단 요청 수

관리자 경로:

보안 관리자
→ 관리자용 AWS WAF
→ 대시보드용 ALB
→ Dashboard Flask EC2

두 진입 경로는 시각적으로 명확하게 분리하고 서로 연결되지 않도록 구성합니다.

### 3. VPC 내부 프라이빗 서브넷

VPC 안에 다음 네 개의 프라이빗 서브넷을 구분하여 표시해 주세요.

#### ① 공격 대상 서비스 서브넷

* K3s 클러스터
* nginx Reverse Proxy
* 자가치유 및 자동 재시작 상태
* 현재 Pod 상태
* CPU 및 메모리 사용률

K3s/nginx는 ③ 쇼핑몰 DB 서브넷의 Flask App Server로 요청을 전달합니다.

연결선 라벨:

* App Port
* Security Group: nginx SG만 허용

#### ② 대시보드 서브넷

* Dashboard Server EC2
* Flask Dashboard
* 보안검사결과 DB 5~10초 주기 조회
* Lambda A
* Lambda B
* Lambda Remediation
* 조치 승인 버튼

대시보드 서버는 ④ 보안검사결과 DB를 조회합니다.

#### ③ 쇼핑몰 DB 서브넷

* Flask App Server EC2
* 쇼핑몰 Flask API
* 쇼핑몰 MySQL Server EC2
* 상품·회원·주문 데이터

연결 흐름:

K3s/nginx
→ Flask App Server
→ 쇼핑몰 MySQL Server

Flask에서 MySQL로 연결되는 선에는 다음 라벨을 표시합니다.

* TCP 3306
* Security Group: Flask SG만 허용

#### ④ 보안검사결과 DB 서브넷

* 보안결과 MySQL Server EC2
* 탐지 결과
* 진단 결과
* 조치 이력

접근 주체:

* Dashboard Flask: 읽기
* Lambda A: 탐지 결과 쓰기
* Lambda B: 분석 결과 쓰기

③ 쇼핑몰 DB와 ④ 보안검사결과 DB 사이에는 연결선이 없어야 하며, 두 데이터 영역이 완전히 분리되어 있음을 표현해 주세요.

### 4. AWS 보안 탐지 서비스

아키텍처 맵의 상단이나 우측에 두 개의 보안 탐지 그룹을 접을 수 있는 패널로 배치해 주세요.

#### 그룹 A: Security Hub 통합

* GuardDuty
* Inspector
* Access Analyzer
* Macie
* AWS Config
* Security Standards / CIS Benchmark
* Security Hub
* EventBridge
* Lambda A

흐름:

GuardDuty / Inspector / Access Analyzer / Macie / AWS Config
→ Security Hub
→ EventBridge
→ Lambda A
→ 보안검사결과 DB

#### 그룹 B: 로그 및 모니터링

* CloudTrail
* CloudWatch
* VPC Flow Logs
* AWS WAF Logs
* Shield Standard
* Lambda B
* S3 원본 로그 저장소

흐름:

로그 서비스
→ Lambda B
→ S3 원본 로그 장기 보관
→ 이상 징후만 보안검사결과 DB에 저장

### 5. 보안 기초 서비스

화면에 작은 Supporting Service 영역을 만들어 다음 상태를 표시해 주세요.

* ACM 인증서 상태
* Secrets Manager
* 쇼핑몰 DB Secret
* 보안결과 DB Secret
* Secrets Manager Interface VPC Endpoint
* 쇼핑몰용 KMS CMK
* 보안결과용 KMS CMK
* S3 암호화 상태
* SSM Session Manager
* SSH 22번 포트 차단 상태

이 서비스들은 특정 서브넷 내부 서버처럼 표현하지 말고, AWS 관리형 서비스 영역으로 표현해 주세요.

## 자산 상태 표현

모든 주요 자산에는 상태 표시기를 추가해 주세요.

* 정상: Blue 또는 Green
* 주의: Yellow
* 위험: Orange
* Critical: Red
* 조치 중: Blue 회전 아이콘
* 연결 끊김: Gray
* 점검 중: Purple

Critical 상태일 때는 다음 효과를 사용합니다.

* 빨간색 테두리
* 왼쪽 상단에 Critical 배지
* 탐지 건수 배지
* 약한 Pulse 애니메이션
* 해당 공격 경로 강조

전체 박스가 계속 깜빡이는 효과는 사용하지 않습니다.

## 탐지 위치와 영향 대상 구분

보안 이벤트가 발생하면 탐지한 서비스와 실제 영향받은 자산을 구분해 주세요.

예시: SQL Injection

* AWS WAF: ‘탐지 위치’ 배지
* Flask App Server: ‘영향 대상’ 배지
* 공격자 → WAF → ALB → K3s → Flask 경로를 빨간색으로 강조
* 차단에 성공한 경우 WAF에는 ‘차단 완료’ 상태 표시
* 추가 조치가 필요한 경우 Flask에는 ‘조치 필요’ 표시

예시: 취약 컨테이너 이미지

* Inspector: ‘탐지 위치’
* Amazon ECR: ‘취약 이미지’
* K3s: ‘배포 영향 대상’

예시: 탈취 자격증명을 이용한 비정상 API 호출

* CloudTrail 또는 GuardDuty: ‘탐지 위치’
* IAM Role 또는 대상 AWS 서비스: ‘영향 대상’

예시: S3 공개 설정

* Access Analyzer: ‘탐지 위치’
* S3: ‘외부 공개’
* Macie: ‘민감정보 포함 가능’

## 표현할 공격 시나리오

다음 보안 이벤트를 샘플 데이터로 활용해 주세요.

1. SQL Injection
2. 디렉터리 스캔
3. 로그인 무차별 대입
4. 탈취 자격증명을 이용한 비정상 API 호출
5. 취약 컨테이너 이미지
6. XSS
7. 포트 스캔
8. S3 버킷 외부 공개 및 비인가 객체 접근

## 오른쪽 영역: 조치 및 상세 패널

오른쪽 패널 상단에 다음 탭을 구성해 주세요.

* 조치 필요
* 탐지 이력
* 조치 이력

기본 탭은 ‘조치 필요’입니다.

### 조치 필요 탭

수동 승인 또는 검토가 필요한 이벤트를 카드 형태로 보여주세요.

각 카드 항목:

* 심각도
* 이벤트명
* 탐지 서비스
* 영향받은 자산
* 탐지 시간
* 미조치 경과 시간
* 현재 상태
* 권장 조치
* 자동 조치 가능 여부

예시 카드:

* SQL Injection 반복 요청
* Flask 취약 패키지 발견
* Security Group 과도한 포트 공개
* 탈취 의심 자격증명 API 호출
* S3 버킷 외부 공개

카드 버튼:

* 상세 보기
* 조치 승인
* 예외 처리

### 아키텍처 자산 클릭

사용자가 아키텍처의 자산을 클릭하면 오른쪽 패널을 상세 화면으로 변경해 주세요.

표시 정보:

* 이벤트명
* 심각도
* 탐지 위치
* 영향받은 자산
* 발생 시각
* 공격자 IP
* 요청 URL 또는 API
* 탐지 규칙
* 현재 차단 여부
* 관련 이벤트 수
* 담당자
* 현재 조치 상태

상세 화면 내부 탭:

* 이벤트 요약
* 원본 로그
* 공격 경로
* 권장 조치
* 조치 이력

원본 로그는 고정폭 폰트의 코드 블록으로 표시하되, 긴 로그 전체를 바로 보여주지 말고 핵심 필드를 강조해 주세요.

## 자동 조치 방식

조치 대상에 따라 실행 방식을 구분해 주세요.

### EC2, K3s, nginx, Flask 조치

Dashboard 조치 승인
→ Lambda Remediation
→ AWS Systems Manager
→ 대상 서버 설정 변경

### AWS 리소스 설정 조치

Dashboard 조치 승인
→ Lambda Remediation
→ AWS API
→ WAF, Security Group, S3 설정 변경

## 조치 승인 Modal

조치 승인 버튼을 누르면 확인 Modal을 표시해 주세요.

Modal 항목:

* 조치 대상
* 탐지 내용
* 현재 설정
* 변경될 설정
* 예상 서비스 영향
* 실행 방식
* 롤백 가능 여부
* 승인자
* 조치 실행 버튼
* 취소 버튼

위험도가 높은 조치는 빨간색 경고 영역과 추가 확인 Checkbox를 표시해 주세요.

## 탐지 이력 탭

필터:

* 전체
* Critical
* High
* Medium
* Low
* 탐지 서비스
* 대상 자산
* 공격 유형
* 기간
* 키워드 검색

테이블 컬럼:

* 탐지 일시
* 심각도
* 이벤트
* 탐지 서비스
* 영향 자산
* 공격자 IP
* 차단 여부
* 조치 상태

## 조치 이력 탭

상태 필터:

* 자동 조치 완료
* 수동 조치 완료
* 승인 대기
* 조치 중
* 미조치
* 조치 실패
* 예외 처리

테이블 컬럼:

* 조치 요청 시각
* 이벤트
* 대상 자산
* 조치 방식
* 승인자
* 실행 결과
* 완료 시각
* 재점검 결과

## 주요 인터랙션

* 5초 간격 실시간 데이터 갱신
* 자동 갱신 ON/OFF
* 아키텍처 확대 및 축소
* 자산 Hover 시 상태 Tooltip
* 자산 클릭 시 상세 패널 전환
* 공격 경로 애니메이션
* 조치 필요 카드 선택 시 관련 자산 강조
* 조치 승인 Modal
* 예외 처리 사유 입력 Modal
* 조치 완료 후 상태를 ‘해결됨’으로 변경
* 해결된 이벤트를 조치 이력으로 자동 이동
* 새로운 Critical 이벤트 발생 시 상단 알림 표시

## 샘플 기본 화면

기본 화면에서는 모든 자산이 정상 상태이며, 오른쪽에 조치 필요 이벤트 3건을 표시해 주세요.

샘플 이벤트:

1. Critical — Flask App Server에서 SQL Injection 반복 탐지
2. High — ECR 이미지에서 취약 패키지 발견
3. High — S3 버킷 외부 공개 설정 탐지

첫 번째 이벤트를 선택하면 다음 자산을 강조해 주세요.

* 공격자 서버
* 쇼핑몰용 WAF
* 쇼핑몰용 ALB
* K3s nginx
* Flask App Server

그리고 오른쪽 상세 패널에는 관련 WAF 로그, 공격자 IP, 요청 URL, 탐지 규칙, 권장 조치를 표시해 주세요.

## 제작할 화면 상태

다음 다섯 가지 화면 또는 Variant를 제작해 주세요.

1. 모든 자산이 정상인 기본 관제 화면
2. SQL Injection Critical 이벤트가 발생한 화면
3. 보안 이벤트 상세 패널이 열린 화면
4. 조치 승인 Modal이 열린 화면
5. 탐지 및 조치 이력 화면

단순한 통계 대시보드가 아니라, 첨부된 AWS 아키텍처의 자산 관계를 실제 보안 이벤트와 연결하여 보여주는 인터랙티브 보안관제 화면으로 제작해 주세요.
