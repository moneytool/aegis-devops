# AWS acceptance run, 2026-09-28

The acceptance run that moved every mapping in `src/aegis_core/compile/actions/aws.yaml` to
`verified: true` (design §6.4, §8). Reproduce with `scripts/aws_acceptance.py`; its docstring
lists the prerequisites.

## Setup

- A fresh AWS Organization; the policies were attached to one **member** account only (SCPs never
  apply to the management account). All test artifacts were removed afterwards; nothing billable
  was created.
- Three test roles in the member account, each with `AdministratorAccess`, so that an explicit SCP
  deny is the only thing that can refuse a call: `aegis-test-agent`, `aegis-test-trusted`,
  `aegis-test-breakglass`.
- `agents.yaml` (deny-by-default, enforce): trusted = the test trusted role, the operator's IAM
  Identity Center role (an ARN with the path `aws-reserved/sso.amazonaws.com/`) and the source
  identity `aegis-test-human`; break-glass = the test break-glass role and
  `OrganizationAccountAccessRole`.
- One acceptance rule per mapped type, all verbs, plus three scoped cases: DynamoDB only in
  `us-west-2` (control: `us-east-1`), S3 buckets only `aegis-prod-*` (control: `aegis-dev-*`), and
  Lambda as `ESCALATE` (must compile to a deny). Compiled: 2 SCPs, 4,893 and 2,930 characters.

## Method

Six identities: the agent; the agent with an untrusted and with a trusted source identity; the
trusted role; the break-glass role; the SSO admin role.

1. **Baseline, no SCP attached**: one real API call per mapped IAM action on a resource that does
   not exist, as every identity. 498 calls, **0 denied** — so any denial afterwards comes from the
   SCP.
2. **Attached**: the same calls, plus calls that would create or change something if allowed
   (`CreateBucket`, `CreateRole`, `CreateUser`, assuming exempt roles, setting a source identity,
   updating an exempt role's trust — each run only as an identity the SCP must deny; the trust
   update re-applies the existing document). `LeaveOrganization` was never called.
3. **IAM policy simulator** (`simulate-principal-policy`, which applies SCPs and reports
   `OrganizationsDecisionDetail`) for every mapped IAM action as every identity, on a concrete ARN,
   with `aws:RequestedRegion` and `aws:SourceIdentity` as context.

Live probes are conclusive only where AWS authorizes before looking the resource up. EC2 instance,
volume and security-group actions, S3, KMS, Route 53 and SQS answer "not found" first, so for
those the simulator is the evidence (`report.json` records which evidence each mapping rests on:
77 live and simulator, 9 live, 4 simulator only).

## Results

- Every exempt identity — including the path-qualified SSO role and the agent session carrying
  the trusted source identity — was allowed on every probe and every simulated action.
- The agent, with or without an untrusted source identity, was denied on every conclusive probe
  (AWS named the service control policy in 62 of 65 denials; EC2's encoded messages do not) and
  on every simulated action; the region and name-glob controls were allowed.
- 90 of 90 mapped IAM actions verified.

## Findings fixed during the run

1. **The full policy did not fit.** One rule per mapped type needed 6 SCPs (4 can attach) because
   every statement repeats the identity condition. Statements now merge exactly, and a rule
   covering every name of a type denies the action on any resource; the same policy fits in 2.
2. **`sts:SetSourceIdentity` was denied outright**, which also stopped an agent whose session
   already carries a source identity from assuming any role (passing it on counts as setting it).
   The self-protection statement now denies only setting an **exempt** value
   (`StringEquals sts:SourceIdentity`). AWS itself refuses to change a session's source identity
   once set (`ValidationError`), which the run confirmed.

Files: `report.json` (per mapping: evidence and verdict), `evidence.json` (every attached probe
and simulator case; account ids redacted).
