# 최신 아키텍처 Terraform 반영 범위

## 반영됨
- ① K3s/nginx만 배치
- ② Dashboard EC2
- ③ Flask App + Shopping MySQL
- ④ Security MySQL
- Shop WAF/ALB와 Admin WAF/ALB 경로 분리
- GuardDuty / Inspector / Access Analyzer / Security Hub
- CloudTrail / VPC Flow Logs / CloudWatch를 지원 데이터 계층으로 유지
- Macie 제외
- Shield Standard는 별도 리소스 미생성
- KMS 정식 Key Policy 반영

## 별도 구현
- Dashboard 애플리케이션
- Lambda A / B / Remediation 코드와 배포
- WAF 로그 분석 후 Security Hub ASFF Finding 변환
- 실제 공격 시나리오
- K3s/nginx/Flask/MySQL 설치 및 앱 배포
