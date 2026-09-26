# Lab 7: IAM Access Analyzer

**Goal:** make Access Analyzer flag a resource accidentally shared externally, resolve
it, and see the least-privilege tooling (unused access + last-accessed data) used to
trim permissions at scale.

## Key concepts

- Access Analyzer uses **automated reasoning** to find resources reachable from
  outside your account/org (roles, S3, KMS, SQS, Secrets Manager, Lambda, and more).
- Two modes: **external access** (who can get in from outside) and **unused access**
  (what to trim for least privilege).
- Intended sharing is handled with **archive rules** so real issues aren't buried.

## Part A: External access

### 1. Variables

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=eu-west-2
echo ${ACCOUNT_ID} ${REGION}
```

### 2. Create an analyzer (ACCOUNT zone of trust)

```bash
aws accessanalyzer create-analyzer \
  --analyzer-name lab-analyzer --type ACCOUNT --region ${REGION}
```

### 3. Create a role that trusts a different account (placeholder 123456789012)

```bash
cat > external-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam create-role --role-name ExternallySharedRole \
  --assume-role-policy-document file://external-trust.json
```

### 4. Let it scan, then list findings (re-run until it appears)

```bash
aws accessanalyzer list-findings-v2 \
  --analyzer-arn arn:aws:access-analyzer:${REGION}:${ACCOUNT_ID}:analyzer/lab-analyzer \
  --query 'findings[?resource!=`null`].[resource,resourceType,status]' \
  --output table
```

You should see a finding for `ExternallySharedRole` with external principal
`123456789012`. In the console (IAM → Access Analyzer) the finding shows who has
access and what they can do.

### 5. Resolve it the right way (fix, since it's unintended)

```bash
cat > internal-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${ACCOUNT_ID}:root" },
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam update-assume-role-policy --role-name ExternallySharedRole \
  --policy-document file://internal-trust.json
```

Wait a couple of minutes and re-run step 4; the finding status becomes `RESOLVED`.
(If external access were *intended*, you'd archive it instead, optionally with an
archive rule.)

## Part B: Least privilege at scale (read-along + free tooling)

### 6. Unused-access analysis (know this; costs per resource, so not created here)

The `ACCOUNT_UNUSED_ACCESS` analyzer type flags:
- unused roles,
- unused permissions within a role,
- unused IAM users, access keys, and passwords.

Workflow: review findings → archive the intended ones (e.g. a real break-glass role)
→ remediate the rest by removing unused permissions.

### 7. Last-accessed data (free, no analyzer)

```bash
JOB=$(aws iam generate-service-last-accessed-details \
  --arn arn:aws:iam::${ACCOUNT_ID}:role/ExternallySharedRole \
  --query JobId --output text)

sleep 5

aws iam get-service-last-accessed-details --job-id ${JOB} \
  --query 'ServicesLastAccessed[?TotalAuthenticatedEntities>`0`].[ServiceName,LastAuthenticated]' \
  --output table
```

A fresh role shows little/no usage. On a busy role, everything absent is a candidate
to remove. Access Analyzer can also **generate a policy** from CloudTrail history
(`aws accessanalyzer start-policy-generation`), turning observed activity into a
scoped draft policy.

### 8. Clean up

```bash
aws iam delete-role --role-name ExternallySharedRole
aws accessanalyzer delete-analyzer --analyzer-name lab-analyzer --region ${REGION}
rm external-trust.json internal-trust.json
```

## Interview talking points

- Provable security / automated reasoning finds resources exposed outside the
  account or org across many resource types.
- Two modes: external access vs unused access. Archive rules keep intended sharing
  out of the way.
- Least-privilege pipeline: unused-access findings + last-accessed data to spot dead
  permissions → policy generation from CloudTrail → review → roll out.
- Deploy an **organization-wide** analyzer from a delegated-admin (security) account
  so one analyzer covers every account.
