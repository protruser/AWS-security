# 01. Terraform 보안 서비스 반영 현황

이 문서는 현재 `wonny-sec` Terraform 코드에
**어떤 AWS 보안 서비스와 보안 기능이 실제로 반영되어 있는지** 정리한 문서입니다.

---

## 1. 한눈에 보기

| 보안 서비스 / 기능  | Terraform 반영 | 현재 구현 수준                                  |
| ------------------- | -------------: | ----------------------------------------------- |
| AWS WAF             |             ✅ | 쇼핑몰/관리자 Web ACL 생성, ALB 연결, 로그 저장 |
| GuardDuty           |             ✅ | Detector 활성화                                 |
| Inspector           |             ✅ | EC2 + ECR 스캔 활성화                           |
| IAM Access Analyzer |             ✅ | Account Analyzer 생성                           |
| Security Hub        |             ✅ | Security Hub 활성화 + 기본 Standards            |
| EventBridge         |             ✅ | Security Hub Finding 이벤트 수신                |
| SNS                 |             ✅ | 보안 알림용 Topic + 이메일 구독                 |
| CloudTrail          |             ✅ | AWS API 활동 로그를 S3에 저장                   |
| VPC Flow Logs       |             ✅ | VPC 트래픽을 CloudWatch Logs에 기록             |
| CloudWatch Logs     |             ✅ | WAF Logs / VPC Flow Logs 저장                   |
| KMS                 |             ✅ | 쇼핑몰용 / 보안결과용 키, 로그 암호화 정책      |
| Secrets Manager     |             ✅ | 쇼핑 DB / 보안 DB 자격증명 저장                 |
| Security Group      |             ✅ | ALB, EC2, DB, Dashboard, Lambda용 SG            |
| SSM Session Manager |             ✅ | EC2 SSH 22번 없이 관리할 수 있는 IAM 권한       |
| Shield Standard     |             ⚪ | AWS 기본 보호이므로 별도 활성화 리소스 없음     |
| Macie               |             ❌ | 최신 7개 시나리오에 직접 매핑되지 않아 제외     |
| Lambda A            |             ❌ | 아직 미구현                                     |
| Lambda B            |             ❌ | 아직 미구현                                     |
| Lambda Remediation  |             ❌ | 아직 미구현                                     |

---

## 2. AWS WAF

### 현재 Terraform에 반영된 것

쇼핑몰용 WAF와 관리자용 WAF를 각각 생성합니다.

```text
Internet
  ├─ Shopping WAF → Shopping ALB
  └─ Admin WAF    → Admin ALB
```

쇼핑몰 WAF에는 현재 다음 규칙이 포함되어 있습니다.

```text
AWSManagedRulesCommonRuleSet
AWSManagedRulesSQLiRuleSet
Rate Limit
```

관리자 WAF에는 다음 규칙이 포함되어 있습니다.

```text
AWSManagedRulesCommonRuleSet
Admin Rate Limit
```

WAF 로그는 CloudWatch Logs에 저장됩니다.

### 7개 시나리오와의 관계

| 시나리오           | 현재 반영 수준                    |
| ------------------ | --------------------------------- |
| SQL Injection      | ✅ SQLi Managed Rule 적용         |
| XSS                | 🟡 Common Rule Set 기반 탐지 가능 |
| 디렉토리 탐색      | 🟡 전용 커스텀 규칙은 아직 없음   |
| 로그인 무차별 대입 | 🟡 Rate Limit 기반 방어는 있음    |

즉 WAF 서비스는 구성되어 있지만,
4개 시나리오 각각에 맞춘 최종 커스텀 판정 로직까지 완성된 것은 아닙니다.

---

## 3. GuardDuty

Terraform에서 GuardDuty Detector를 활성화합니다.

현재 구성 목적:

```text
포트 스캔
탈취 자격증명 관련 이상행위
```

GuardDuty는 AWS 관리형 탐지 서비스이므로
별도의 "포트스캔 규칙"을 Terraform에서 직접 만드는 구조가 아닙니다.

현재 상태:

```text
GuardDuty 활성화                    ✅
실제 공격 발생                      별도
Finding 발생 확인                    별도
Finding을 Security DB에 저장         아직 미구현
```

---

## 4. Inspector

Terraform에서 Amazon Inspector를 활성화하고
다음 리소스 타입을 검사하도록 구성합니다.

```text
EC2
ECR
```

프로젝트의 7개 시나리오 중:

```text
취약 컨테이너 이미지
```

시나리오에 직접 연결됩니다.

현재 상태:

```text
Inspector 활성화         ✅
EC2 스캔                 ✅
ECR 스캔                 ✅
취약 이미지 업로드/검증   별도
Finding DB 저장          아직 미구현
```

---

## 5. IAM Access Analyzer

Account 단위 Access Analyzer를 생성합니다.

목적은 외부 접근 가능성이나 과도한 접근 경로를 분석하는 것입니다.

프로젝트에서는:

```text
탈취 자격증명(퇴사자)
```

시나리오에서 GuardDuty의 보조 증빙 역할로 사용합니다.

현재 상태:

```text
Analyzer 생성             ✅
분석 기능 활성화          ✅
퇴사자 전용 커스텀 판정    아직 미구현
```

---

## 6. Security Hub

Terraform에서 Security Hub를 활성화하고
기본 Security Standards를 사용합니다.

현재 역할:

```text
GuardDuty
Inspector
Access Analyzer
      ↓
Security Hub
      ↓
EventBridge
      ↓
SNS
      ↓
Email
```

현재 Terraform에는 다음까지 반영되어 있습니다.

```text
Security Hub 활성화              ✅
기본 Standards                   ✅
Security Hub EventBridge Rule    ✅
SNS Topic                        ✅
Email Subscription               ✅
```

아직 없는 부분:

```text
Security Hub
      ↓
Lambda A
      ↓
Security MySQL
```

즉 Finding을 DB에 저장하는 수집 Lambda는 아직 구현하지 않았습니다.

---

## 7. EventBridge / SNS

Security Hub Finding 이벤트를 EventBridge가 받아
SNS로 전달하도록 구성되어 있습니다.

```text
Security Hub Finding
       ↓
EventBridge
       ↓
SNS
       ↓
Email
```

SNS Topic은 보안용 KMS Key로 암호화됩니다.

현재 상태:

```text
EventBridge Rule          ✅
EventBridge Target        ✅
SNS Topic                 ✅
Email Subscription        ✅
```

이메일 주소를 설정했다면 AWS에서 받은
SNS Subscription Confirmation 메일의 승인 링크를 눌러야 합니다.

---

## 8. CloudTrail

CloudTrail을 생성해 AWS API 활동 기록을
보안 로그 S3 버킷에 저장합니다.

```text
AWS API 활동
    ↓
CloudTrail
    ↓
Security Log S3
```

CloudTrail은 공격을 직접 판정하는 서비스라기보다
감사 및 보안 분석을 위한 데이터 소스 역할입니다.

현재 상태:

```text
CloudTrail 생성           ✅
S3 저장                   ✅
Log File Validation       ✅
KMS 기반 보호             ✅
```

---

## 9. VPC Flow Logs

VPC 전체 트래픽에 대해 Flow Logs를 활성화합니다.

```text
VPC Network Traffic
        ↓
VPC Flow Logs
        ↓
CloudWatch Logs
```

현재 설정은:

```text
traffic_type = ALL
```

이므로 ACCEPT / REJECT 흐름을 모두 기록합니다.

프로젝트에서는 포트 스캔 분석 등의
보조 네트워크 데이터로 활용할 수 있습니다.

---

## 10. CloudWatch Logs

현재 CloudWatch Logs에 저장되는 주요 로그:

```text
Shopping WAF Logs
Admin WAF Logs
VPC Flow Logs
```

각 Log Group은 보안용 고객 관리형 KMS Key를 사용합니다.

KMS Key Policy에서는 CloudWatch Logs 서비스에 필요한 권한을 부여하고,
Encryption Context를 이용해 프로젝트의 특정 Log Group만
해당 키를 사용할 수 있도록 제한합니다.

---

## 11. KMS

Terraform에서 KMS Key를 2개 생성합니다.

```text
Shopping Data KMS Key
Security Data KMS Key
```

Security KMS Key는 다음에 사용됩니다.

```text
CloudWatch Logs
Security Log S3
SNS
Security 관련 EBS / Secrets
```

현재 수정본에는 다음 서비스에 필요한 Key Policy를 포함합니다.

```text
CloudWatch Logs
EventBridge → encrypted SNS
CloudTrail
```

---

## 12. Secrets Manager

두 DB의 자격증명을 분리해서 관리합니다.

```text
Shopping DB Secret
Security DB Secret
```

권한 역시 역할별로 분리합니다.

```text
Flask App / Shopping DB
        ↓
Shopping DB Secret

Dashboard / Security DB
        ↓
Security DB Secret
```

---

## 13. Security Group / SSM

### Security Group

서비스 간 필요한 경로만 허용하도록 분리합니다.

```text
Shopping ALB → K3s/nginx
K3s/nginx   → Flask App
Flask App   → Shopping MySQL

Admin ALB   → Dashboard
Dashboard   → Security MySQL
```

### SSM

EC2에 SSH 22번 인바운드를 열지 않고
SSM Session Manager를 사용할 수 있도록
각 EC2용 IAM Role에 다음 정책을 연결합니다.

```text
AmazonSSMManagedInstanceCore
```

---

## 14. Shield Standard

Shield Standard는 AWS에서 기본으로 제공되는 보호이므로
Terraform에서 별도의 `enable` 리소스를 만들지 않습니다.

따라서:

```text
Terraform resource 생성   ❌
AWS 기본 보호             ✅
```

로 이해하면 됩니다.

---

## 15. Macie

Macie는 최신 7개 보안 시나리오에 직접 매핑되지 않아
현재 Terraform에서는 제외했습니다.

```text
Macie Terraform Resource  ❌
```

---

## 16. 아직 Terraform에 없는 보안 기능

### Lambda A

목표 구조:

```text
Security Hub
     ↓
EventBridge
     ↓
Lambda A
     ↓
Security MySQL
```

현재:

```text
미구현
```

### Lambda B

목표 구조:

```text
WAF Logs
CloudTrail
VPC Flow Logs
CloudWatch
     ↓
Lambda B
     ↓
Custom Analysis
     ↓
Security MySQL
```

현재:

```text
미구현
```

### Lambda Remediation

목표 구조:

```text
Dashboard 승인
      ↓
Lambda Remediation
      ↓
SSM
      ↓
EC2 보안 조치
```

현재:

```text
미구현
```

---

## 17. 현재 7개 보안 시나리오 구현 수준

| 번호 | 시나리오             | 담당 서비스                 | 현재 상태              |
| ---- | -------------------- | --------------------------- | ---------------------- |
| 1    | SQL Injection        | WAF                         | ✅ 기반 구현           |
| 2    | XSS                  | WAF                         | 🟡 Common Rule 기반    |
| 3    | 디렉토리 탐색        | WAF                         | 🟡 전용 규칙 필요      |
| 4    | 로그인 무차별 대입   | WAF                         | 🟡 Rate Limit 기반     |
| 5    | 포트 스캔            | GuardDuty                   | ✅ 서비스 활성화       |
| 6    | 탈취 자격증명        | GuardDuty + Access Analyzer | 🟡 서비스 기반만 구성  |
| 7    | 취약 컨테이너 이미지 | Inspector                   | ✅ EC2/ECR 검사 활성화 |

---

## 18. 현재 보안 구현 위치

```text
[보안 인프라 생성]
WAF
GuardDuty
Inspector
Access Analyzer
Security Hub
CloudTrail
VPC Flow Logs
CloudWatch
SNS
KMS
        ✅ 현재 여기까지

            ↓

[다음 구현]
Lambda A
Finding → Security DB

            ↓

Lambda B
Logs → Custom Analysis → Security DB

            ↓

Dashboard 표시

            ↓

Lambda Remediation
SSM 자동 조치
```

---

## 19. 한 문장 정리

현재 Terraform은

> **AWS 보안 서비스를 생성하고 로그와 Finding을 수집할 수 있는 기반 인프라까지 구축한 상태이며, 다음 단계에서 Lambda를 이용한 Finding/로그 수집, Security DB 저장, 시나리오별 세부 판정 및 자동 조치를 구현해야 한다.**
