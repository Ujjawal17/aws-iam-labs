# Lab 1: Identity vs resource policies

**Goal:** see that a bucket policy alone can grant access in the same account, and
how a permission boundary changes that. Then see the subtle case where granting the
*session* ARN bypasses the boundary.

## Key concepts

- **Same account:** identity policy allow **OR** resource policy allow is enough
  (a union), unless something explicitly denies.
- **Permission boundary:** caps what identity-based permissions can grant. Its
  implicit deny still limits a resource grant made to a **role ARN**, but **not** a
  grant made to a **session ARN** or an IAM user ARN.
- **Explicit deny** anywhere always wins.

## Steps

### 1. Variables (keep this terminal open for the whole lab)

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET=iam-lab-${ACCOUNT_ID}
REGION=eu-west-2
echo ${ACCOUNT_ID} ${BUCKET}
```

### 2. Create a role with zero permissions

```bash
cat > trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${ACCOUNT_ID}:root" },
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam create-role --role-name LabRole --assume-role-policy-document file://trust.json
```

### 3. Create a CLI profile that assumes the role (fixed session name)

```bash
aws configure set role_arn arn:aws:iam::${ACCOUNT_ID}:role/LabRole --profile labrole
aws configure set source_profile default --profile labrole
aws configure set role_session_name lab-session --profile labrole

aws sts get-caller-identity --profile labrole
# ARN should end in assumed-role/LabRole/lab-session
```

### 4. Create a bucket and upload a test file

```bash
aws s3 mb s3://${BUCKET} --region ${REGION}
echo "hello from the lab" > test.txt
aws s3 cp test.txt s3://${BUCKET}/
```

### 5. Try to read as the role — expect AccessDenied

```bash
aws s3api get-object --bucket ${BUCKET} --key test.txt out.txt --profile labrole
```

Read the full error; AWS often names which policy type caused the denial.

### 6. Add a bucket policy naming the role, then retry — expect SUCCESS

```bash
cat > bucket-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${ACCOUNT_ID}:role/LabRole" },
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::${BUCKET}/*"
  }]
}
EOF

aws s3api put-bucket-policy --bucket ${BUCKET} --policy file://bucket-policy.json
aws s3api get-object --bucket ${BUCKET} --key test.txt out.txt --profile labrole
```

Succeeds even though the role has no identity policy — the same-account union rule.

### 7. Attach an EC2-only permission boundary, then retry — expect AccessDenied

```bash
cat > boundary.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow", "Action": "ec2:*", "Resource": "*" }]
}
EOF

aws iam create-policy --policy-name EC2OnlyBoundary --policy-document file://boundary.json
aws iam put-role-permissions-boundary --role-name LabRole \
  --permissions-boundary arn:aws:iam::${ACCOUNT_ID}:policy/EC2OnlyBoundary

sleep 10
aws s3api get-object --bucket ${BUCKET} --key test.txt out.txt --profile labrole
```

### 8. Grant the *session* ARN instead of the role ARN — expect SUCCESS

```bash
sed -i.bak "s|arn:aws:iam::${ACCOUNT_ID}:role/LabRole|arn:aws:sts::${ACCOUNT_ID}:assumed-role/LabRole/lab-session|" bucket-policy.json
cat bucket-policy.json

aws s3api put-bucket-policy --bucket ${BUCKET} --policy file://bucket-policy.json
aws s3api get-object --bucket ${BUCKET} --key test.txt out.txt --profile labrole
```

Per AWS docs this succeeds despite the boundary, because the grant goes directly to
the session, which the boundary's implicit deny does not limit.

### 9. Clean up

```bash
aws s3 rm s3://${BUCKET} --recursive
aws s3api delete-bucket-policy --bucket ${BUCKET}
aws s3 rb s3://${BUCKET}
aws iam delete-role-permissions-boundary --role-name LabRole
aws iam delete-role --role-name LabRole
aws iam delete-policy --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/EC2OnlyBoundary
rm trust.json bucket-policy.json bucket-policy.json.bak boundary.json test.txt out.txt
```

Also remove the `[profile labrole]` section from `~/.aws/config`.

## Interview talking points

- Same-account access is a union of identity and resource policies; cross-account is
  an intersection (both sides must allow).
- A permission boundary caps identity permissions; it limits a resource grant to a
  role ARN but not to a session ARN or user ARN.
- The full AWS error message often tells you which policy type denied a request.
