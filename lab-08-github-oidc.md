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

## Troubleshooting: "Not authorized to perform sts:AssumeRoleWithWebIdentity"

This single error covers *every* claim mismatch — the token reached AWS but a trust
condition didn't match. It never says which one. Work through it like this.

### Step 1: Decode the REAL token claims (do this first, don't guess)

Add a step to the workflow that fetches and decodes the OIDC token, so you see exactly
what GitHub sent rather than what you assume it sent:

```yaml
      - name: Decode OIDC token
        run: |
          TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r '.value')
          echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{sub, aud, repository, ref}'
```

The `permissions: id-token: write` block must be present or `$ACTIONS_ID_TOKEN_REQUEST_*`
won't exist. Compare the printed `sub`/`aud` against your trust policy character by
character. Common mismatches:

- **Repo name typo** (e.g. `aws-iam-lab` vs `aws-iam-labs`). The commonest cause.
- **Wrong branch:** token `sub` ends in `refs/heads/master` but policy pins `main`.
- **Case sensitivity:** `sub` matching is case-sensitive; GitHub sends canonical casing.
- **Custom `sub` format with immutable IDs** — see below.

### Step 2: The immutable-ID gotcha (a real one worth knowing)

Some orgs/repos enable **"include enterprise/immutable identifiers in the OIDC subject
claim."** Then the token `sub` is NOT the documented `repo:ORG/REPO:ref:...`. It looks
like:

```
repo:my-user@12345678/my-repo@987654321:ref:refs/heads/main
```

The `@<number>` suffixes are the immutable numeric user/org ID and repo ID. A trust policy
written with `StringEquals` on the plain `repo:ORG/REPO:...` string will **fail closed**
against this. It's actually a security feature (the numeric IDs survive a repo rename,
so an attacker can't re-create a repo with your name to inherit trust), but you must
account for it.

**Fix with `StringLike` and wildcards for the numeric parts**, keeping owner, repo, and
ref pinned:

```json
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
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:MyOrg@*/my-repo@*:ref:refs/heads/main"
      }
    }
  }]
}
```

Note `aud` stays in `StringEquals` (exact match); only `sub` moves to `StringLike`
because it now contains variable numeric IDs. Alternatively, hardcode the exact `sub`
including the IDs — even more secure, but ugly and repo-specific.

### Step 3: Verify the provider and audience

- Confirm the OIDC provider's client-ID list contains the audience:
  ```bash
  PROVIDER_ARN=$(aws iam list-open-id-connect-providers \
    --query 'OpenIDConnectProviderList[0].Arn' --output text)
  aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$PROVIDER_ARN" \
    --query '{clientIDs:ClientIDList, url:Url}' --output json
  # clientIDs must include sts.amazonaws.com
  ```
- If the decoded `aud` is anything other than `sts.amazonaws.com`, either set
  `audience: sts.amazonaws.com` on the `configure-aws-credentials` step, or match the
  policy to whatever audience the token actually carries.

### Step 4: Rule out timing and org policy

- Trust-policy edits usually apply in seconds but can lag a minute — `sleep 30` and
  push a fresh commit (`git commit --allow-empty`) rather than re-running the old run.
- If you're in a **member** account, an SCP/RCP could deny `sts:AssumeRoleWithWebIdentity`.
  If `describe-organization` shows the master account == your account, you're in the
  management account and SCPs don't apply — rule it out.

### The wildcard patterns, summarized

| Pattern | `sub` value | Who can assume | Verdict |
|---|---|---|---|
| Pinned branch | `repo:O/R:ref:refs/heads/main` | only main | Good |
| Pinned + immutable IDs | `repo:O@*/R@*:ref:refs/heads/main` (StringLike) | only main | Good (needed if custom sub) |
| Environment | `repo:O/R:environment:production` | only that env (add reviewers) | Best |
| **Wildcard ref** | `repo:O/R:*` (StringLike) | **any branch, any fork PR** | **Dangerous** |
| Wildcard repo | `repo:O/*:*` | any repo in the org | Very dangerous |

Use wildcards **only** for the immutable-ID numeric suffixes, never to widen the ref or
repo. `repo:O/R:*` is the classic finding: it lets an attacker's feature branch or a
fork's pull-request run assume your role.

## Interview talking points

- OIDC federation removes long-lived CI keys — the single biggest CI credential risk.
  This is the fix you'd propose for a leaked-CI-key incident (see Lab 4 root cause).
- The `sub` condition is the boundary: **pin org, repo, and ref/environment**. A
  wildcard ref lets any branch or fork PR assume the role.
- Always require the `aud` = `sts.amazonaws.com` condition (keep it in `StringEquals`).
- For production, prefer environment-scoped subjects plus GitHub environment protection
  rules over branch-scoped ones.
- The same OIDC pattern applies to GitLab, Terraform Cloud, and any OIDC-capable CI.
- **The token `sub` isn't always the documented format.** Orgs can enable immutable
  numeric IDs (`repo:owner@123/repo@456:...`) or fully custom `sub` templates, so a
  `StringEquals` policy written against the assumed format fails closed. Decode and
  verify the real claims rather than assuming them — the
  `curl $ACTIONS_ID_TOKEN_REQUEST_URL ... | base64 -d | jq` trick is how you debug this
  in production. This is a strong hands-on detail to mention.
