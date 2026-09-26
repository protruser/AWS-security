# KMS 수정 내역

이번 버전은 최초 배포에서 발생했던 CloudWatch Logs + KMS `AccessDeniedException`을 수정한 버전입니다.

## 수정한 내용

- `aws_kms_key.security`에 명시적 Key Policy 추가
- `logs.${var.region}.amazonaws.com` 서비스 principal 허용
- CloudWatch Logs 권한을 아래 3개 Log Group ARN으로 제한
  - `aws-waf-logs-${var.project}-shop`
  - `aws-waf-logs-${var.project}-admin`
  - `/${var.project}/vpc-flow`
- EventBridge → 암호화된 SNS Topic 전송에 필요한 KMS 권한 추가
- CloudTrail → KMS 암호화 S3 로그 버킷 사용에 필요한 KMS 권한 추가
- 기존 `kms_key_id = aws_kms_key.security.arn` 설정은 유지

## 처음 배포할 때

```cmd
copy terraform.tfvars.example terraform.tfvars
notepad terraform.tfvars
terraform init
terraform fmt
terraform validate
terraform plan -out=review.tfplan
terraform apply review.tfplan
```

## 기존 구성을 이 파일로 교체한 경우

기존 `.tfstate`를 유지한 채 파일만 교체한 뒤:

```cmd
terraform fmt
terraform validate
terraform plan
```

으로 변경 내용을 확인한 후 적용하세요.

`terraform.tfstate`를 삭제하거나 새 폴더에서 기존 AWS 리소스에 그대로 apply하면 중복 생성 문제가 생길 수 있습니다.
