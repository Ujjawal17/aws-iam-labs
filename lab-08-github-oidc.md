# Lab 8: GitHub Actions OIDC federation

**Goal:** replace long-lived CI access keys with short-lived credentials via OIDC, and
see how a too-loose trust condition lets *any* repo (or any GitHub user) assume your
role. This is the highest-value lab for an IaC-heavy cloud security role: misconfigured
OIDC trust is a classic finding and a classic interview question.

**Deployable?** Yes, fully, if you have a GitHub repo to test from. The role and OIDC
provider setup is deployable with the CLI alone; the *assume* step needs a GitHub
Actions workflow (a minimal one is included). You can also study it as a
control-reference without running the workflow.

## Key concepts

- GitHub Actions can request an **OIDC token** from GitHub identifying the workflow's
  repo, branch, environment, etc. AWS trusts GitHub as an OIDC identity provider and
  lets the workflow assume a role — **no stored AWS keys**.
- The trust policy's **`sub` (subject) condition** is the security boundary. Get it
  wrong and the door is wide open.
- Two conditions matter:
  - `token.actions.githubusercontent.com:aud` must equal `sts.amazonaws.com`.
  - `token.actions.githubusercontent.com:sub` must pin the exact repo **and** the
    ref/environment allowed to assume the role.

## The dangerous misconfigurations (what interviewers probe)

1. **Wildcard repo:** `repo:*` or `repo:my-org/*:*` — any repo in the org, or any repo
   anywhere, can assume the role.
2. **Wildcard ref:** `repo:my-org/my-repo:*` — any branch, tag, or PR from that repo,
   including an attacker's PR branch, can assume it. Pull-request runs are the common
   abuse here.
3. **Missing `aud` condition** — weakens validation.
4. **Trusting the wrong provider thumbprint** (historically) — largely handled by AWS
   now, but know the concept.

## Steps (deployable)

### 1. Variables

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
GH_ORG=your-github-username-or-org      # <-- edit
GH_REPO=your-repo-name                  # <-- edit
echo ${ACCOUNT_ID} ${GH_ORG}/${GH_REPO}
```

### 2. Create the GitHub OIDC identity provider (one per account)

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com
# If it already exists you'll get EntityAlreadyExists — that's fine, skip.
```

### 3. Create a role with a TIGHT trust policy

Pin both the repo and the ref. This example allows only the `main` branch.

```bash
cat > gh-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::${ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:${GH_ORG}/${GH_REPO}:ref:refs/heads/main"
      }
    }
  }]
}
EOF

aws iam create-role --role-name GitHubActionsRole --assume-role-policy-document file://gh-trust.json

# Give it something harmless to prove access works
aws iam attach-role-policy --role-name GitHubActionsRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

### 4. Minimal GitHub Actions workflow to test it

Commit this as `.github/workflows/oidc-test.yml` in your repo. Replace the account ID.

```yaml
name: oidc-test
on:
  push:
    branches: [ main ]
permissions:
  id-token: write        # REQUIRED for OIDC
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::ACCOUNT_ID:role/GitHubActionsRole
          aws-region: eu-west-2
      - run: aws sts get-caller-identity && aws s3 ls
```

Push to `main`: the job should succeed and print an assumed-role identity, with no AWS
keys stored anywhere in GitHub.

### 5. Demonstrate the vulnerability (loosen the ref)

Change the `sub` to a wildcard ref and observe that a branch or PR that should NOT have
access now can:

```bash
sed -i.bak 's|:ref:refs/heads/main|:*|' gh-trust.json
aws iam update-assume-role-policy --role-name GitHubActionsRole --policy-document file://gh-trust.json
```

Now `repo:ORG/REPO:*` matches **any** ref — including `pull_request` runs from forks
or an attacker's feature branch. If your repo accepts external PRs and runs this
workflow on them, that's an escalation path to your AWS account.

### 6. Re-tighten (the fix)

```bash
# Back to a pinned ref, or pin an environment instead:
#   "sub": "repo:ORG/REPO:environment:production"
sed -i 's|:\*"|:ref:refs/heads/main"|' gh-trust.json
aws iam update-assume-role-policy --role-name GitHubActionsRole --policy-document file://gh-trust.json
```

Stronger patterns:
- Pin an **environment**: `repo:ORG/REPO:environment:production`, combined with
  GitHub environment protection rules (required reviewers).
- Never run privileged OIDC jobs on `pull_request` from forks.
- Use `StringLike` only when you genuinely need a pattern, and keep the org/repo fixed.

### 7. Clean up

```bash
aws iam detach-role-policy --role-name GitHubActionsRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
aws iam delete-role --role-name GitHubActionsRole
# Optional: remove the OIDC provider if nothing else uses it
aws iam delete-open-id-connect-provider \
  --open-id-connect-provider-arn arn:aws:iam::${ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com
rm gh-trust.json gh-trust.json.bak
```

Delete the workflow file from your repo too.

## Interview talking points

- OIDC federation removes long-lived CI keys — the single biggest CI credential risk.
  This is the fix you'd propose for a leaked-CI-key incident (see Lab 4 root cause).
- The `sub` condition is the boundary: **pin org, repo, and ref/environment**. A
  wildcard ref lets any branch or fork PR assume the role.
- Always require the `aud` = `sts.amazonaws.com` condition.
- For production, prefer environment-scoped subjects plus GitHub environment protection
  rules over branch-scoped ones.
- The same OIDC pattern applies to GitLab, Terraform Cloud, and any OIDC-capable CI.
