# AWS IAM Security Labs

Hands-on labs for practising AWS IAM concepts that come up in cloud security
interviews. Each lab is self-contained: it sets up a scenario, walks through an
attack or misconfiguration, applies the fix, and cleans up everything it created.

All labs run from the AWS CLI and cost approximately nothing (IAM is free; the
few S3 objects and SSM parameters used are tiny). Lab 7 uses IAM Access Analyzer,
whose external-access analyzer is free.

## Before you start

- **Use a sandbox account**, never one with real workloads. Some labs deliberately
  create risky permissions.
- **Do not sign in as the root user.** The root user cannot assume roles, so the
  tests will fail. Use an IAM or IAM Identity Center user with admin access.
- **Set a budget alert** (Billing → Budgets → a small monthly budget with email alert)
  as basic hygiene.
- **Use bash**, not zsh. In zsh, `$VAR:role` is misread as a modifier; always write
  `${VAR}` to be safe. The labs already use `${...}` throughout.
- If output opens in a pager, run `export AWS_PAGER=""` once to turn that off.

## The labs

| # | Topic | Core concept |
|---|-------|--------------|
| 1 | [Identity vs resource policies](lab-01-identity-vs-resource-policies.md) | Same-account union rule; permission boundaries; session-ARN grants |
| 2 | [Trust, ExternalId, confused deputy](lab-02-trust-externalid-confused-deputy.md) | Cross-account trust; the confused deputy problem; ExternalId |
| 3 | [PassRole privilege escalation](lab-03-passrole-privilege-escalation.md) | `iam:PassRole` escalation via Lambda; scoping the fix |
| 4 | [Revoking active sessions](lab-04-revoking-active-sessions.md) | You can't delete a temp credential; `aws:TokenIssueTime` revocation |
| 5 | [Region-lockdown policy trap](lab-05-region-lockdown-scp.md) | Global services and `aws:RequestedRegion`; `NotAction` fix |
| 6 | [ABAC and tag tampering](lab-06-abac-tag-tampering.md) | Tag-based access; whoever controls tags controls access |
| 7 | [IAM Access Analyzer](lab-07-access-analyzer.md) | External-access findings; unused access; least privilege at scale |

## Safety note

These files contain **no real account IDs, credentials, or output**. The account ID
is always written as `${ACCOUNT_ID}`, resolved at runtime from
`aws sts get-caller-identity`. Keep it that way if you edit them, and never commit
captured command output, which may contain access keys or session tokens.
