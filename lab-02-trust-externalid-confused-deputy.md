# Lab 2: Trust policies, ExternalId and the confused deputy

**Goal:** recreate the confused deputy setup with a "vendor" role and a "customer"
role in one account, then close it with an ExternalId condition.

## Key concepts

- Trusting `...:root` trusts the **whole account**, delegating the decision to that
  account's admins. A principal there can assume the role only if its own identity
  policy also allows it (cross-account intersection).
- **Confused deputy:** a shared vendor service that assumes roles in many customer
  accounts can be tricked into assuming *your* role on an attacker's behalf, because
  role ARNs are guessable.
- **ExternalId:** a per-customer secret the vendor sends on every AssumeRole call.
  The vendor must generate it (customers choosing their own would defeat it).

## Steps

### 1. Variables

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo ${ACCOUNT_ID}
```

### 2. Create VendorRole (the "deputy") + a profile to act as it

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

aws iam create-role --role-name VendorRole --assume-role-policy-document file://trust-root.json
aws configure set role_arn arn:aws:iam::${ACCOUNT_ID}:role/VendorRole --profile vendor
aws configure set source_profile default --profile vendor
aws sts get-caller-identity --profile vendor
```

### 3. Create CustomerDataRole, trusting the whole account

```bash
aws iam create-role --role-name CustomerDataRole --assume-role-policy-document file://trust-root.json
```

**Test A — can VendorRole assume CustomerDataRole?** (Predict first.)

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::${ACCOUNT_ID}:role/CustomerDataRole \
  --role-session-name testA --profile vendor \
  --query AssumedRoleUser.Arn
```

### 4. Narrow the trust to VendorRole specifically

```bash
cat > trust-vendor.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${ACCOUNT_ID}:role/VendorRole" },
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam update-assume-role-policy --role-name CustomerDataRole --policy-document file://trust-vendor.json
sleep 10
```

**Test B — same command, new trust policy.** (This is the confused deputy setup.)

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::${ACCOUNT_ID}:role/CustomerDataRole \
  --role-session-name testB --profile vendor \
  --query AssumedRoleUser.Arn
```

### 5. Add an ExternalId condition

```bash
cat > trust-externalid.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${ACCOUNT_ID}:role/VendorRole" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "cust-7f3a9b21" } }
  }]
}
EOF

aws iam update-assume-role-policy --role-name CustomerDataRole --policy-document file://trust-externalid.json
sleep 10
```

**Tests C, D, E — no ID / wrong ID / correct ID.** (Predict all three.)

```bash
# C: no ExternalId (attacker who only knows your role ARN)
aws sts assume-role --role-arn arn:aws:iam::${ACCOUNT_ID}:role/CustomerDataRole \
  --role-session-name testC --profile vendor --query AssumedRoleUser.Arn

# D: wrong ExternalId
aws sts assume-role --role-arn arn:aws:iam::${ACCOUNT_ID}:role/CustomerDataRole \
  --role-session-name testD --profile vendor --external-id cust-attacker01 \
  --query AssumedRoleUser.Arn

# E: correct ExternalId
aws sts assume-role --role-arn arn:aws:iam::${ACCOUNT_ID}:role/CustomerDataRole \
  --role-session-name testE --profile vendor --external-id cust-7f3a9b21 \
  --query AssumedRoleUser.Arn
```

### 6. (Optional) Delete and recreate VendorRole, then inspect the trust policy

```bash
aws iam delete-role --role-name VendorRole
aws iam create-role --role-name VendorRole --assume-role-policy-document file://trust-root.json
aws iam get-role --role-name CustomerDataRole --query Role.AssumeRolePolicyDocument
```

Observe how the principal is stored: deleting and recreating a role gives it a new
internal unique ID, so a trust policy that named the old role no longer resolves to
the new one. This is a deliberate protection against role re-creation attacks.

### 7. Inspect the evidence (console)

CloudTrail → Event history → filter Event name = AssumeRole. Compare a successful
and a failed event: look at `userIdentity`, `requestParameters`, `errorCode`.
(Event history works with no trail configured.)

### 8. Clean up

```bash
aws iam delete-role --role-name CustomerDataRole
aws iam delete-role --role-name VendorRole
rm trust-root.json trust-vendor.json trust-externalid.json
```

Then remove the `[profile vendor]` section from `~/.aws/config`.

## Note on failed-assume error codes

Tests A, C and D all fail with the same generic `AccessDenied` — STS does not reveal
*why* (missing permission vs missing ExternalId vs wrong ExternalId). This is
deliberate: a specific error would be an oracle an attacker could use to confirm a
valid role and brute-force the ExternalId.

## Interview talking points

- Trusting `:root` = trusting the account, not just its root user.
- Confused deputy is a top risk for any multi-tenant vendor integration; ExternalId
  (vendor-generated, per customer) is the standard mitigation.
- Also narrow the principal to the vendor's specific role ARN and apply least
  privilege to what the role can read.
