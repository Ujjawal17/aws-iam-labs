# Lab 6: ABAC and tag tampering

**Goal:** grant a role access to resources tagged for its own "team", then break the
model by retagging a resource it shouldn't touch, then fix it. Uses SSM parameters
(free, instant, tag-aware).

## Key concepts

- ABAC grants access when a resource tag matches a principal tag, e.g.
  `aws:ResourceTag/team == ${aws:PrincipalTag/team}`.
- **Whoever controls the tags controls the access.** A broad tagging permission is
  effectively a permission-granting permission.
- Fix has two halves: protect the **resource** side (deny writes to the `team` tag
  key) and the **principal** side (lock down `sts:TagSession`, `iam:TagRole` so an
  attacker can't change their *own* tag).

## Steps

### 1. Variables

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=eu-west-2
echo ${ACCOUNT_ID} ${REGION}
```

### 2. Create two parameters, tagged for different teams

```bash
aws ssm put-parameter --name /lab/payments/secret --value "payments-data" \
  --type String --region ${REGION} --tags Key=team,Value=payments

aws ssm put-parameter --name /lab/search/secret --value "search-data" \
  --type String --region ${REGION} --tags Key=team,Value=search
```

### 3. Create the "payments engineer" role (session tagging allowed)

```bash
cat > abac-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${ACCOUNT_ID}:root" },
    "Action": ["sts:AssumeRole", "sts:TagSession"]
  }]
}
EOF

aws iam create-role --role-name PaymentsEngineer --assume-role-policy-document file://abac-trust.json
```

### 4. Attach the ABAC policy (deliberately vulnerable tagging rule)

Note the `\${aws:PrincipalTag/team}` — the backslash stops the shell expanding it so
the literal policy variable reaches IAM.

```bash
cat > abac-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOwnTeamParams",
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:GetParameters"],
      "Resource": "*",
      "Condition": {
        "StringEquals": { "aws:ResourceTag/team": "\${aws:PrincipalTag/team}" }
      }
    },
    {
      "Sid": "OverlyBroadTagging",
      "Effect": "Allow",
      "Action": ["ssm:AddTagsToResource", "ssm:RemoveTagsFromResource"],
      "Resource": "*"
    },
    {
      "Sid": "DescribeForConvenience",
      "Effect": "Allow",
      "Action": "ssm:DescribeParameters",
      "Resource": "*"
    }
  ]
}
EOF

aws iam put-role-policy --role-name PaymentsEngineer --policy-name ABAC --policy-document file://abac-policy.json

# Verify the policy variable survived intact:
aws iam get-role-policy --role-name PaymentsEngineer --policy-name ABAC \
  --query 'PolicyDocument.Statement[0].Condition'
```

### 5. Helper — assume the role with a payments session tag

```bash
as_payments() {
  CREDS=$(aws sts assume-role \
    --role-arn arn:aws:iam::${ACCOUNT_ID}:role/PaymentsEngineer \
    --role-session-name eng-session \
    --tags Key=team,Value=payments \
    --query Credentials --output json)
  AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId) \
  AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey) \
  AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken) \
  "$@"
}
```

### 6. Confirm ABAC works as intended

```bash
as_payments aws ssm get-parameter --name /lab/payments/secret --region ${REGION} --query Parameter.Value  # succeeds
as_payments aws ssm get-parameter --name /lab/search/secret   --region ${REGION} --query Parameter.Value  # denied
```

### 7. The attack — retag the victim resource, then read it

```bash
as_payments aws ssm add-tags-to-resource \
  --resource-type Parameter --resource-id /lab/search/secret \
  --tags Key=team,Value=payments --region ${REGION}

as_payments aws ssm get-parameter --name /lab/search/secret --region ${REGION} --query Parameter.Value
```

Now succeeds and prints `search-data` — a team boundary crossed with only a tagging
permission.

### 8. Fix — deny writes to the `team` tag key

```bash
cat > abac-policy-fixed.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOwnTeamParams",
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:GetParameters"],
      "Resource": "*",
      "Condition": {
        "StringEquals": { "aws:ResourceTag/team": "\${aws:PrincipalTag/team}" }
      }
    },
    {
      "Sid": "DescribeForConvenience",
      "Effect": "Allow",
      "Action": "ssm:DescribeParameters",
      "Resource": "*"
    },
    {
      "Sid": "DenyTeamTagWrites",
      "Effect": "Deny",
      "Action": ["ssm:AddTagsToResource", "ssm:RemoveTagsFromResource"],
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringEquals": { "aws:TagKeys": "team" }
      }
    }
  ]
}
EOF

aws iam put-role-policy --role-name PaymentsEngineer --policy-name ABAC --policy-document file://abac-policy-fixed.json
sleep 10
```

### 9. Reset the victim tag, then prove the attack is blocked

```bash
# Reset as admin (not as the role)
aws ssm add-tags-to-resource --resource-type Parameter \
  --resource-id /lab/search/secret --tags Key=team,Value=search --region ${REGION}

# Attack again — now denied
as_payments aws ssm add-tags-to-resource \
  --resource-type Parameter --resource-id /lab/search/secret \
  --tags Key=team,Value=payments --region ${REGION}

# Legit read still works
as_payments aws ssm get-parameter --name /lab/payments/secret --region ${REGION} --query Parameter.Value
```

### 10. Clean up

```bash
aws ssm delete-parameter --name /lab/payments/secret --region ${REGION}
aws ssm delete-parameter --name /lab/search/secret --region ${REGION}
aws iam delete-role-policy --role-name PaymentsEngineer --policy-name ABAC
aws iam delete-role --role-name PaymentsEngineer
rm abac-trust.json abac-policy.json abac-policy-fixed.json
```

## Interview talking points

- ABAC collapses if tagging permissions aren't controlled; tagging a resource is
  effectively granting access to it.
- Fix both sides: deny writes to the `team` tag key (resource side) and lock down
  `sts:TagSession` / `iam:TagRole` (principal side).
- Tag-on-create (`aws:RequestTag` with `ec2:CreateAction`) lets people tag at creation
  but never re-tag afterwards.
- Detection: CloudTrail alert on tag writes touching the `team` key.
