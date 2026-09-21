# 00. Terraform 실행방법 설명서 (Windows CMD 기준)

이 문서는 `wonny-sec` AWS 보안 모니터링 프로젝트의 Terraform을
**처음 받는 사람도 Windows CMD에서 그대로 따라 실행할 수 있도록** 정리한 안내서입니다.

---

## 1. 이 Terraform이 만드는 것

Terraform을 실행하면 AWS에 아래 인프라가 생성됩니다.

- VPC `10.0.0.0/16`
- Public Subnet 2개
- Private Subnet 4개
- Internet Gateway
- NAT Gateway 1개
- Route Table
- EC2 5대
  - ① K3s/nginx용 EC2
  - ② Dashboard용 EC2
  - ③ Flask App용 EC2
  - ③ Shopping MySQL용 EC2
  - ④ Security MySQL용 EC2
- Shopping WAF / ALB
- Admin WAF / ALB
- Security Group
- IAM Role / Instance Profile
- SSM Session Manager 권한
- KMS
- Secrets Manager
- S3
- ECR
- CloudTrail
- VPC Flow Logs
- CloudWatch Logs
- GuardDuty
- Inspector
- IAM Access Analyzer
- Security Hub
- EventBridge
- SNS

> 주의: Terraform은 AWS 인프라를 만드는 역할입니다.
> K3s 설치, nginx 배포, Flask 쇼핑몰 코드, Dashboard 코드, MySQL 초기 스키마,
> Lambda A/B/Remediation 코드는 별도로 구현해야 합니다.

---

## 2. 실행 전에 필요한 프로그램

Windows CMD에서 아래 명령이 모두 동작해야 합니다.

```cmd
aws --version
terraform -version
```

둘 다 버전이 나오면 준비가 된 것입니다.

### AWS CLI가 없다면

AWS CLI v2를 설치한 뒤 CMD를 다시 열고 확인합니다.

```cmd
aws --version
```

### Terraform이 없다면

Terraform Windows AMD64 버전을 설치하고
`terraform.exe`가 있는 폴더를 Windows `Path` 환경변수에 추가합니다.

설치 후 CMD를 다시 열고:

```cmd
terraform -version
```

---

## 3. AWS CLI 로그인 설정

CMD에서:

```cmd
aws configure
```

다음 순서대로 입력합니다.

```text
AWS Access Key ID: 본인 IAM Access Key ID
AWS Secret Access Key: 본인 IAM Secret Access Key
Default region name: ap-northeast-2
Default output format: json
```

Secret Access Key는 절대 GitHub, 메신저, 문서에 올리지 않습니다.

설정 확인:

```cmd
aws sts get-caller-identity
```

정상이라면 AWS Account와 ARN이 출력됩니다.

---

## 4. 프로젝트 폴더로 이동

압축을 예를 들어 Downloads에 풀었다면:

```cmd
cd /d C:\Users\user\Downloads\wonny-sec-terraform
```

현재 파일 확인:

```cmd
dir
```

다음과 같은 파일들이 보이면 정상입니다.

```text
network.tf
compute.tf
security_groups.tf
alb_waf.tf
security_services.tf
variables.tf
terraform.tfvars.example
README.md
00_실행방법_설명서.md
```

---

## 5. terraform.tfvars 만들기

예제 파일을 실제 설정 파일로 복사합니다.

```cmd
copy terraform.tfvars.example terraform.tfvars
```

메모장으로 엽니다.

```cmd
notepad terraform.tfvars
```

---

## 6. terraform.tfvars에서 반드시 확인할 값

처음 실행 시 아래 항목을 확인합니다.

### 6-1. 리전

서울 리전이면 그대로 둡니다.

```hcl
region = "ap-northeast-2"
```

### 6-2. 프로젝트 이름

기본값 그대로 사용해도 됩니다.

```hcl
project = "wonny-sec"
```

### 6-3. 관리자 접근 IP

아래 값은 예제이므로 반드시 실제 공인 IP로 변경합니다.

```hcl
admin_cidrs = ["203.0.113.10/32"]
```

현재 공인 IP 확인:

```cmd
curl https://checkip.amazonaws.com
```

예를 들어 결과가:

```text
123.45.67.89
```

라면:

```hcl
admin_cidrs = ["123.45.67.89/32"]
```

로 변경합니다.

### 6-4. 이메일 알림

SNS 이메일 알림을 받을 주소를 넣습니다.

```hcl
notification_email = "my-email@example.com"
```

사용하지 않을 경우:

```hcl
notification_email = ""
```

### 6-5. 도메인이 없는 경우

현재 도메인이 없다면 아래 값을 그대로 유지합니다.

```hcl
enable_custom_domain = false
route53_zone_id      = ""
shop_domain          = ""
admin_domain         = ""
```

이 경우 ALB 기본 DNS 주소를 사용합니다.

### 6-6. 보안 서비스

GuardDuty, Inspector, Access Analyzer, Security Hub를 Terraform에서 생성하려면:

```hcl
enable_security_services = true
```

처음 네트워크/EC2만 확인하고 싶다면 일시적으로:

```hcl
enable_security_services = false
```

로 바꿀 수 있습니다.

### 6-7. VPC Endpoint

비용 절감을 위해 처음에는 다음 값을 권장합니다.

```hcl
enable_vpc_endpoints = false
```

---

## 7. Terraform 초기화

프로젝트 폴더에서:

```cmd
terraform init
```

정상이면 마지막에 비슷한 문구가 나옵니다.

```text
Terraform has been successfully initialized!
```

---

## 8. Terraform 코드 정리

```cmd
terraform fmt
```

Terraform 파일의 형식을 자동으로 정리합니다.

---

## 9. Terraform 문법 검사

```cmd
terraform validate
```

정상이라면:

```text
Success! The configuration is valid.
```

가 출력됩니다.

오류가 나오면 `apply` 하지 말고 먼저 오류를 수정합니다.

---

## 10. 실제 생성 전 Plan 확인

```cmd
terraform plan -out=review.tfplan
```

이 명령은 AWS에 실제로 생성하지 않고,
무엇을 생성할지 미리 보여줍니다.

마지막에 예를 들어:

```text
Plan: XX to add, 0 to change, 0 to destroy.
```

가 나옵니다.

반드시 생성 예정 리소스를 검토합니다.

---

## 11. 실제 AWS 인프라 생성

Plan 내용에 문제가 없으면:

```cmd
terraform apply review.tfplan
```

이 명령부터 실제 AWS 리소스가 생성됩니다.

완료되면:

```text
Apply complete!
```

가 표시됩니다.

---

## 12. 생성 결과 확인

```cmd
terraform output
```

예를 들어 아래 정보가 출력됩니다.

```text
shop_url
admin_url
shop_alb_dns
admin_alb_dns
private_subnet_ids
security_log_bucket
ecr_repositories
vpc_id
```

도메인이 없는 경우 `shop_url`, `admin_url`은 ALB 기본 DNS를 사용합니다.

---

## 13. 현재 단계에서 화면이 바로 안 떠도 정상

Terraform 실행 직후에는 아래 인프라만 생성됩니다.

```text
VPC / Subnet / EC2 / ALB / WAF / IAM / S3 / KMS / 보안 서비스
```

하지만 다음 프로그램은 아직 설치되지 않습니다.

- K3s
- nginx
- Flask 쇼핑몰
- MySQL
- Dashboard 애플리케이션
- Lambda A
- Lambda B
- Lambda Remediation

따라서 ALB URL에 접속해도 503 또는 Target Unhealthy 상태가 나올 수 있습니다.

---

## 14. 아키텍처 배치

```text
Internet
  |
  +-- Shopping WAF
  |      |
  |    Shopping ALB
  |      |
  |    ① K3s/nginx
  |      |
  |    ③ Flask App
  |      |
  |    ③ Shopping MySQL
  |
  +-- Admin WAF
         |
       Admin ALB
         |
       ② Dashboard EC2
         |
       ④ Security MySQL
```

Public Subnet:

```text
10.0.10.0/24
10.0.20.0/24
```

Private Subnet:

```text
① 10.0.1.0/24
② 10.0.2.0/24
③ 10.0.3.0/24
④ 10.0.4.0/24
```

NAT Gateway는 1개입니다.

---

## 15. KMS 관련 구성

보안용 KMS Key는 다음 서비스가 사용할 수 있도록 Key Policy가 포함되어 있습니다.

- CloudWatch Logs
- EventBridge → SNS
- CloudTrail

CloudWatch Logs는 프로젝트에서 사용하는 특정 Log Group ARN만
Encryption Context 조건으로 허용합니다.

---

## 16. 삭제 전 확인

AWS 비용 방지를 위해 테스트가 끝났다면 삭제합니다.

먼저 삭제 예정 목록 확인:

```cmd
terraform plan -destroy -out=destroy.tfplan
```

마지막에:

```text
Plan: 0 to add, 0 to change, XX to destroy.
```

가 표시됩니다.

기존에 Terraform으로 만들지 않은 리소스가 삭제 목록에 없는지 확인합니다.

---

## 17. 실제 삭제

```cmd
terraform apply destroy.tfplan
```

완료 후:

```cmd
terraform state list
```

아무것도 출력되지 않으면 Terraform이 관리하던 리소스가 모두 제거된 것입니다.

---

## 18. 삭제 시 자주 발생하는 문제

### 18-1. S3 BucketNotEmpty

예:

```text
BucketNotEmpty: The bucket you tried to delete is not empty.
```

S3 Versioning 때문에 이전 객체 버전이 남아 있을 수 있습니다.

AWS Console에서:

```text
S3
→ 해당 security-logs 버킷
→ Empty
→ 모든 객체/버전 삭제
```

후 다시:

```cmd
terraform plan -destroy -out=destroy2.tfplan
terraform apply destroy2.tfplan
```

을 실행합니다.

### 18-2. Inspector 삭제 Timeout

예:

```text
Inspector Enabler ... IN_PROGRESS
```

상태 확인:

```cmd
aws inspector2 batch-get-account-status --account-ids <AWS_ACCOUNT_ID> --region ap-northeast-2
```

`DISABLED`가 될 때까지 잠시 기다린 뒤 destroy를 다시 실행합니다.

---

## 19. 중요한 파일 관리

GitHub에 올리면 안 되는 파일:

```text
terraform.tfvars
terraform.tfstate
terraform.tfstate.backup
*.tfplan
.env
*.pem
```

특히 Terraform State에는 비밀번호 등 민감정보가 포함될 수 있습니다.

---

## 20. 가장 짧은 실행 순서

처음 실행:

```cmd
copy terraform.tfvars.example terraform.tfvars
notepad terraform.tfvars

terraform init
terraform fmt
terraform validate
terraform plan -out=review.tfplan
terraform apply review.tfplan
terraform output
```

삭제:

```cmd
terraform plan -destroy -out=destroy.tfplan
terraform apply destroy.tfplan
terraform state list
```

---

## 21. 문제가 생겼을 때

오류가 발생하면 바로 다시 `apply`를 반복하지 말고
오류 메시지의 첫 번째 `Error:` 블록부터 확인합니다.

특히 다음 키워드를 확인합니다.

```text
AccessDenied
KMS
BucketNotEmpty
TargetGroup
SecurityGroup
Inspector
CloudWatch Logs
```

오류를 수정한 뒤에는 보통:

```cmd
terraform fmt
terraform validate
terraform plan -out=review2.tfplan
terraform apply review2.tfplan
```

순서로 다시 진행합니다.
