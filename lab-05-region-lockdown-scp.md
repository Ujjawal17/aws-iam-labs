# Lab 5: Region-lockdown policy and the global-services trap

**Goal:** see why a naive "deny everything outside eu-west-1" policy breaks global
services, and fix it with `NotAction`. Run as a single-account simulation (an inline
policy on one role) that reproduces the `aws:RequestedRegion` behaviour of a real SCP.

## Key concepts

- Global services (IAM, Organizations, Route 53, CloudFront, STS global endpoint,
  Support, Billing, Cost Explorer, WAF) are served from `us-east-1`, so their calls
  carry `aws:RequestedRegion = us-east-1` regardless of where your workloads run.
- A blanket region deny therefore breaks them. Fix with `NotAction` to exempt them.
- Real SCPs differ: they apply account/OU-wide, never grant, and **never apply to the
  management account**.

## Steps

### 1. Variables

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo ${ACCOUNT_ID}
```

### 2. Create a broad role + a profile to use it

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

aws iam create-role --role-name RegionLabRole --assume-role-policy-document file://trust-root.json
aws iam attach-role-policy --role-name RegionLabRole \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

aws configure set role_arn arn:aws:iam::${ACCOUNT_ID}:role/RegionLabRole --profile region
aws configure set source_profile default --profile region
```

### 3. Baseline — all three should work

```bash
aws s3 ls --profile region --region eu-west-1
aws ec2 describe-instances --profile region --region eu-west-2 --query 'Reservations[].Instances[].InstanceId'
aws iam list-roles --profile region --max-items 1 --query 'Roles[].RoleName'
```

### 4. Apply the naive region-lockdown policy

```bash
cat > region-deny-naive.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": { "StringNotEquals": { "aws:RequestedRegion": "eu-west-1" } }
  }]
}
EOF

aws iam put-role-policy --role-name RegionLabRole \
  --policy-name RegionLock --policy-document file://region-deny-naive.json
sleep 10
```

### 5. See what broke (predict each)

```bash
aws s3 ls --profile region --region eu-west-1                                            # A: allowed (in-region)
aws ec2 describe-instances --profile region --region eu-west-2 \
  --query 'Reservations[].Instances[].InstanceId'                                        # B: denied (intended)
aws iam list-roles --profile region --max-items 1 --query 'Roles[].RoleName'            # C: denied (the BUG)
```

C breaks because IAM is global (us-east-1), caught by the deny.

### 6. Apply the fixed policy — exempt global services with NotAction

```bash
cat > region-deny-fixed.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "NotAction": [
      "iam:*", "organizations:*", "route53:*", "cloudfront:*",
      "sts:*", "support:*", "budgets:*", "ce:*", "waf:*", "wafv2:*"
    ],
    "Resource": "*",
    "Condition": { "StringNotEquals": { "aws:RequestedRegion": "eu-west-1" } }
  }]
}
EOF

aws iam put-role-policy --role-name RegionLabRole \
  --policy-name RegionLock --policy-document file://region-deny-fixed.json
sleep 10
```

### 7. Confirm the fix

```bash
aws s3 ls --profile region --region eu-west-1                                            # A: still allowed
aws ec2 describe-instances --profile region --region eu-west-2 \
  --query 'Reservations[].Instances[].InstanceId'                                        # B: still denied (goal)
aws iam list-roles --profile region --max-items 1 --query 'Roles[].RoleName'            # C: works again
```

### 8. Clean up

```bash
aws iam delete-role-policy --role-name RegionLabRole --policy-name RegionLock
aws iam detach-role-policy --role-name RegionLabRole \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
aws iam delete-role --role-name RegionLabRole
rm trust-root.json region-deny-naive.json region-deny-fixed.json
```

Then remove the `[profile region]` section from `~/.aws/config`.

## How this differs from a real SCP (say this in interview)

- **Scope:** an SCP hits every principal in an account/OU at once — which is why a bad
  one is dangerous and you test on an empty OU first.
- **SCPs never grant;** they only filter what identity policies can allow.
- **Management account is exempt** from all SCPs.
- Real region-deny policies also exempt a break-glass role via `aws:PrincipalArn`, and
  AWS publishes a maintained example policy worth starting from.

## Interview talking points

- Name the specific global services and the `us-east-1` mechanism.
- `Action: *` vs `NotAction: [...]` is the whole fix.
- Blast-radius discipline: empty test OU → one throwaway account → verify both the
  intended block and that global services still work → roll out gradually.
