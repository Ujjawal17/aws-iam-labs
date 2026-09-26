# Lab 10: Data perimeter

**Goal:** understand the three questions a data perimeter answers and practise the
deployable pieces (identity perimeter on a bucket via `aws:PrincipalOrgID`; network
perimeter via a VPC endpoint policy). The full perimeter uses SCPs/RCPs, which need
Organizations — those parts are covered as control-reference.

**Deployable?** Partly. The `aws:PrincipalOrgID` bucket condition is deployable in any
account (you just need your org ID, or use `aws:PrincipalAccount` if standalone). The
VPC-endpoint and RCP parts are described as controls to know.

## The data perimeter model

A data perimeter enforces three guarantees. Learn the grid — interviewers love it:

| | Trusted identities | Trusted resources | Expected network |
|---|---|---|---|
| **Goal** | Only my org's principals | Only my org's resources | Only from my networks |
| **On identities (SCP)** | — | `aws:ResourceOrgID` | `aws:SourceVpc`, `aws:SourceIp` |
| **On resources (RCP / policy)** | `aws:PrincipalOrgID` | — | `aws:SourceVpce` |
| **On networks (endpoint policy)** | `aws:PrincipalOrgID` | `aws:ResourceOrgID` | — |

- **Trusted identities:** your resources are only accessed by principals in your org
  (blocks a leaked credential used by an outsider, and cross-account confused-deputy).
- **Trusted resources:** your principals can only touch your org's resources (blocks
  exfiltration to an attacker-controlled bucket).
- **Expected networks:** access only from your VPCs/known IPs (blocks stolen
  credentials used from elsewhere — ties back to Lab-4 style theft).

## Part A (deployable): identity perimeter on a bucket

Restrict a bucket so only principals in your org can read it, regardless of their IAM
permissions.

### 1. Variables

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=eu-west-2
BUCKET=perimeter-lab-${ACCOUNT_ID}
# If you're in an org, get the org id; otherwise we'll pin the account instead.
ORG_ID=$(aws organizations describe-organization --query 'Organization.Id' --output text 2>/dev/null)
echo "Account=${ACCOUNT_ID} Org=${ORG_ID:-<none>}"
```

### 2. Create a bucket with a data-perimeter policy

If you have an org id, use `aws:PrincipalOrgID`. If standalone, swap the condition for
`"aws:PrincipalAccount": "${ACCOUNT_ID}"` to see the same behaviour.

```bash
aws s3 mb s3://${BUCKET} --region ${REGION}
echo "sensitive" > secret.txt
aws s3 cp secret.txt s3://${BUCKET}/

# Org-based version (edit the value if standalone as noted above):
cat > perimeter-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyOutsideOrg",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::${BUCKET}",
      "arn:aws:s3:::${BUCKET}/*"
    ],
    "Condition": {
      "StringNotEquals": { "aws:PrincipalOrgID": "${ORG_ID}" }
    }
  }]
}
EOF

aws s3api put-bucket-policy --bucket ${BUCKET} --policy file://perimeter-policy.json
```

### 3. Test

```bash
# As yourself (inside the org) — still works:
aws s3 cp s3://${BUCKET}/secret.txt -   # prints "sensitive"
```

Any principal outside the org is denied even if their own IAM policy allows S3 and even
if a bucket ACL or another statement would have allowed them. The explicit deny wins.
(If you have a second account outside the org, assume a role there and confirm the deny.)

### 4. Clean up Part A

```bash
aws s3 rm s3://${BUCKET} --recursive
aws s3 rb s3://${BUCKET}
rm secret.txt perimeter-policy.json
```

## Part B (control-reference): network perimeter via VPC endpoint policy

Attach an **endpoint policy** to your S3 gateway/interface VPC endpoint so traffic
through it can only reach your org's buckets — blocking exfiltration to a foreign
bucket even from inside your VPC:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": "*",
    "Condition": { "StringEquals": { "aws:ResourceOrgID": "${ORG_ID}" } }
  }]
}
```

And the reciprocal control on the **resource** side: require requests to arrive via your
endpoint with `"aws:SourceVpce": "vpce-xxxx"`, so stolen credentials used from the
internet fail. This is the same idea as the Lab-4 stolen-credential problem, solved at
the network layer.

## Part C (control-reference): SCPs and RCPs

- **SCP with `aws:ResourceOrgID`:** stop *your* principals from writing to buckets/
  resources outside your org (the trusted-resources guarantee) — anti-exfiltration.
- **RCP (Resource Control Policy):** the newer counterpart to SCPs. An SCP is an
  org-wide guardrail on **identities**; an **RCP is an org-wide guardrail on
  resources**. An RCP with `aws:PrincipalOrgID` enforces "only my org's principals can
  access any of my org's S3 buckets/roles/etc." centrally, instead of writing the
  condition into every individual resource policy. Supported for a growing set of
  services (S3, STS, SQS, KMS, Secrets Manager, and more). Mentioning RCPs signals you
  are current with AWS.

## Interview talking points

- Recite the 3x3 grid: trusted identities / trusted resources / expected networks,
  each enforced on identities, resources, or networks.
- Key condition keys: `aws:PrincipalOrgID`, `aws:ResourceOrgID`, `aws:SourceVpc`,
  `aws:SourceVpce`, `aws:SourceIp`, `aws:PrincipalIsAWSService` (to exempt AWS
  services in deny-based perimeters).
- RCPs vs SCPs: resource-side vs identity-side org guardrails. Use RCPs to enforce the
  identity perimeter centrally rather than per-resource.
- This is defense-in-depth: even if IAM is misconfigured or a credential leaks, the
  perimeter still blocks out-of-org access and out-of-network use.
