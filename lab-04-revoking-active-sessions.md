# Lab 4: Revoking active sessions

**Goal:** learn the most counterintuitive part of IAM incident response — you cannot
delete a temporary credential, so you invalidate it by policy using
`aws:TokenIssueTime`. Steal a session, watch it work, kill it, then confirm fresh
sessions still work.

## Key concepts

- There is **no API** to revoke an individual STS token; it is valid until it expires.
- You deny by `aws:TokenIssueTime`: an explicit deny for every credential issued
  **before** a chosen cutoff. This is exactly what the console "Revoke sessions"
  button does.
- It is fail-safe: legitimate users simply re-authenticate to get a fresh,
  post-cutoff session.
- **Caveat:** revoking sessions on one role is not full containment. Also kill any
  long-term keys the attacker created and any other roles they assumed, in the same
  window.

## Steps

### 1. Variables

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo ${ACCOUNT_ID}
```

### 2. Create a role with one harmless canary permission

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

aws iam create-role --role-name RevokeLabRole --assume-role-policy-document file://trust-root.json

cat > canary.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*" }]
}
EOF

aws iam put-role-policy --role-name RevokeLabRole --policy-name Canary --policy-document file://canary.json
```

### 3. Steal a session

```bash
sleep 5   # ensure the stolen session's issue time is clearly before the later cutoff

CREDS=$(aws sts assume-role --role-arn arn:aws:iam::${ACCOUNT_ID}:role/RevokeLabRole \
        --role-session-name stolen-session --query Credentials --output json)
STOLEN_AKID=$(echo $CREDS | jq -r .AccessKeyId)
STOLEN_SECRET=$(echo $CREDS | jq -r .SecretAccessKey)
STOLEN_TOKEN=$(echo $CREDS | jq -r .SessionToken)
echo "Stolen key: ${STOLEN_AKID}"
```

### 4. Confirm the stolen credentials work

```bash
AWS_ACCESS_KEY_ID=$STOLEN_AKID \
AWS_SECRET_ACCESS_KEY=$STOLEN_SECRET \
AWS_SESSION_TOKEN=$STOLEN_TOKEN \
aws s3 ls
```

### 5. The naive response that isn't enough

```bash
aws iam delete-role-policy --role-name RevokeLabRole --policy-name Canary
sleep 10

AWS_ACCESS_KEY_ID=$STOLEN_AKID \
AWS_SECRET_ACCESS_KEY=$STOLEN_SECRET \
AWS_SESSION_TOKEN=$STOLEN_TOKEN \
aws s3 ls
```

Removing the permission stops *this* action, but in reality the attacker has likely
already assumed other roles or made other credentials, and stripping permissions
breaks your own workloads. Re-add the canary to demonstrate the proper fix:

```bash
aws iam put-role-policy --role-name RevokeLabRole --policy-name Canary --policy-document file://canary.json
sleep 10
```

### 6. The correct response — revoke by issue time

```bash
CUTOFF=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "Revoking sessions issued before ${CUTOFF}"

cat > revoke.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": { "DateLessThan": { "aws:TokenIssueTime": "${CUTOFF}" } }
  }]
}
EOF

aws iam put-role-policy --role-name RevokeLabRole --policy-name RevokeOldSessions --policy-document file://revoke.json
sleep 10
```

### 7. Confirm the stolen session is dead — expect AccessDenied

```bash
AWS_ACCESS_KEY_ID=$STOLEN_AKID \
AWS_SECRET_ACCESS_KEY=$STOLEN_SECRET \
AWS_SESSION_TOKEN=$STOLEN_TOKEN \
aws s3 ls
```

### 8. Confirm legitimate users are unaffected — expect SUCCESS

```bash
sleep 5   # ensure the new session is clearly issued after the cutoff

CREDS2=$(aws sts assume-role --role-arn arn:aws:iam::${ACCOUNT_ID}:role/RevokeLabRole \
         --role-session-name fresh-session --query Credentials --output json)

AWS_ACCESS_KEY_ID=$(echo $CREDS2 | jq -r .AccessKeyId) \
AWS_SECRET_ACCESS_KEY=$(echo $CREDS2 | jq -r .SecretAccessKey) \
AWS_SESSION_TOKEN=$(echo $CREDS2 | jq -r .SessionToken) \
aws s3 ls
```

A fresh session (issued after the cutoff) works, while the stolen one stays dead.

### 9. Clean up

```bash
aws iam delete-role-policy --role-name RevokeLabRole --policy-name Canary 2>/dev/null
aws iam delete-role-policy --role-name RevokeLabRole --policy-name RevokeOldSessions
aws iam delete-role --role-name RevokeLabRole
rm trust-root.json canary.json revoke.json
```

## Interview talking points

- No API deletes a single STS token; deny by `aws:TokenIssueTime` to invalidate every
  session issued before a moment. The console button is exactly this.
- It is fail-safe for legitimate users, who re-authenticate for a fresh session.
- Full containment also kills attacker-created long-term keys and any other assumed
  roles — all at once, or the attacker walks back in.
- Long-term access keys never expire, which is why attackers create them for
  persistence.
