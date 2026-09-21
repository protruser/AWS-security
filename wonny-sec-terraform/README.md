# 먼저 읽어주세요

Windows CMD 기준 상세 실행방법은 **`00_실행방법_설명서.md`**,
명령어만 빠르게 보고 싶다면 **`00_빠른실행.txt`**를 먼저 확인하세요.

---

보안 서비스가 현재 어디까지 Terraform에 반영되어 있는지는 **`01_보안서비스_반영현황.md`**를 확인하세요.

# wonny-sec Terraform — 최신 아키텍처 반영본

현재 최신 아키텍처에서 **Terraform으로 만들 수 있는 AWS 인프라**만 구성한 버전입니다.

## 최신 배치

```text
Internet
 ├─ WAF(shop)  → ALB(shop)  → ① K3s/nginx → ③ Flask App → ③ Shopping MySQL
 └─ WAF(admin) → ALB(admin) → ② Dashboard EC2 → ④ Security MySQL
```

### Private Subnet

| 번호 | CIDR | 배치 |
|---|---|---|
| ① 공격 대상 서비스 | 10.0.1.0/24 | K3s / nginx EC2 |
| ② 대시보드 | 10.0.2.0/24 | Dashboard EC2 |
| ③ 쇼핑몰 DB | 10.0.3.0/24 | Flask App EC2 + Shopping MySQL EC2 |
| ④ 보안검사결과 DB | 10.0.4.0/24 | Security MySQL EC2 |

**Flask App Server는 ①이 아니라 ③에 있습니다.**

## Terraform이 만드는 것

- VPC `10.0.0.0/16`
- Public Subnet 2개 (ALB용, 2 AZ)
- Private Subnet 4개
- IGW / NAT Gateway / Route Table
- EC2 5대
  - K3s/nginx
  - Dashboard
  - Flask App
  - Shopping MySQL
  - Security MySQL
- 쇼핑몰 WAF + ALB
- 관리자 WAF + ALB
- Security Group
- IAM Role / Instance Profile / SSM Session Manager 권한
- KMS 2개
- Secrets Manager
- S3 보안 로그 버킷
- ECR 3개
- CloudTrail
- VPC Flow Logs
- WAF Logs / CloudWatch Logs
- GuardDuty
- Inspector EC2/ECR
- IAM Access Analyzer
- Security Hub
- Security Hub EventBridge → SNS
- 선택형 Route53 + ACM + HTTPS
- 선택형 VPC Endpoint
- 선택형 GitHub Actions OIDC 배포 Role

## 최신 7개 보안 시나리오 매핑

| 시나리오 | 주 탐지/차단 서비스 |
|---|---|
| SQL Injection | WAF |
| XSS | WAF |
| 디렉토리 탐색 | WAF |
| 로그인 무차별 대입 | WAF |
| 포트 스캔 | GuardDuty |
| 탈취 자격증명(퇴사자) | GuardDuty + IAM Access Analyzer 보조 증빙 |
| 취약 컨테이너 이미지 | Inspector |

### 역할 정리

- **WAF**: 쇼핑몰 HTTP 공격 시나리오 4개를 직접 매핑.
- **GuardDuty**: 포트 스캔, 자격증명 악용 관련 탐지.
- **Inspector**: EC2/ECR 취약점 스캔.
- **IAM Access Analyzer**: 외부/과도한 접근 가능성에 대한 보조 증빙.
- **Security Hub**: 지원되는 finding을 통합하는 허브.
- **CloudTrail**: 이벤트 로그/감사 데이터 소스.
- **VPC Flow Logs**: 네트워크 흐름 기록용 보조 데이터.
- **CloudWatch**: 로그/지표/알람 집계.
- **Shield Standard**: AWS 기본 DDoS 보호. 별도 Terraform 활성화 리소스를 만들지 않음.
- **Macie**: 최신 7개 시나리오에 직접 매핑되지 않아 제외.

> WAF는 자체적으로 Security Hub ASFF finding을 직접 생성하지 않습니다.
> WAF 로그를 Security Hub finding으로 변환하려면 별도의 Lambda/백엔드 로직이 필요합니다.

## Dashboard 범위

Terraform은 아래까지만 담당합니다.

```text
Admin WAF
   ↓
Admin ALB
   ↓
② Dashboard EC2
   ↓
④ Security DB
```

Dashboard Flask 코드, 화면, 그래프, API, DB 조회 로직은 별도로 구축합니다.

## Terraform에 아직 넣지 않은 애플리케이션/운영 로직

- K3s 설치 및 nginx Deployment
- Flask 쇼핑몰 애플리케이션 코드
- Dashboard 애플리케이션 코드
- MySQL 설치 / 초기 스키마
- Lambda A 코드
- Lambda B 코드
- Lambda Remediation 코드
- SSM 자동조치 문서 내용
- 7개 공격 시나리오 실행 코드
- WAF 로그 → Security Hub Finding 변환 로직

## KMS 정식 구성

보안용 KMS Key Policy에 다음 서비스의 사용 권한을 포함합니다.

- CloudWatch Logs
  - 쇼핑몰 WAF Log Group
  - 관리자 WAF Log Group
  - VPC Flow Log Group
- EventBridge → KMS 암호화 SNS
- CloudTrail → KMS 암호화 S3

CloudWatch Logs는 Encryption Context로 위 프로젝트 Log Group ARN만 사용하도록 제한합니다.

## 도메인이 없는 경우

기본 설정:

```hcl
enable_custom_domain = false
route53_zone_id      = ""
shop_domain          = ""
admin_domain         = ""
```

이때는 ALB 기본 DNS를 사용합니다.

```cmd
terraform output shop_url
terraform output admin_url
```

## Windows CMD 실행

```cmd
copy terraform.tfvars.example terraform.tfvars
notepad terraform.tfvars

terraform init
terraform fmt
terraform validate
terraform plan -out=review.tfplan
terraform apply review.tfplan
```

삭제 전 확인:

```cmd
terraform plan -destroy -out=destroy.tfplan
```

실제 삭제:

```cmd
terraform apply destroy.tfplan
```

## 주의

- NAT Gateway, ALB, WAF, EC2, 로그, 보안 서비스 등에 비용이 발생할 수 있습니다.
- SSH 22 인바운드는 만들지 않습니다. SSM Session Manager를 사용합니다.
- `terraform.tfstate`, `.tfplan`, `.tfvars`, `.env`, `.pem`은 Git에 올리지 마세요.
- 계정 단위 보안 서비스가 이미 활성화되어 있으면 기존 리소스를 무심코 덮어쓰지 않도록 plan을 반드시 검토하세요.
