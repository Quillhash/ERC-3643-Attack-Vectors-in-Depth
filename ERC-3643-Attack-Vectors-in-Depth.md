# ERC-3643 Attack Vectors in Depth

Companion to the [main checklist](README.md). Each vector: what it is, why T-REX is exposed, how it plays out, and what mitigates it. Implementation-agnostic — applies to the reference suite and forks alike.

## Index

1. [Trusted issuer compromise](#1-trusted-issuer-compromise)
2. [Claim forgery and replay](#2-claim-forgery-and-replay)
3. [Registry manipulation](#3-registry-manipulation)
4. [Compliance state desync](#4-compliance-state-desync)
5. [Malicious or buggy compliance modules](#5-malicious-or-buggy-compliance-modules)
6. [Agent privilege abuse](#6-agent-privilege-abuse)
7. [Recovery flow abuse](#7-recovery-flow-abuse)
8. [Freeze accounting attacks](#8-freeze-accounting-attacks)
9. [Shared identity storage contamination](#9-shared-identity-storage-contamination)
10. [Implementation Authority takeover](#10-implementation-authority-takeover)
11. [Transfer-path asymmetry](#11-transfer-path-asymmetry)
12. [Launch misconfiguration](#12-launch-misconfiguration)

---

## 1. Trusted issuer compromise

**What.** The entire compliance model reduces to "claims signed by trusted issuers are true." If an issuer's signing key leaks, or a registry owner adds a rogue issuer, attackers mint themselves valid KYC/accreditation claims and pass `isVerified` legitimately.

**Why T-REX is exposed.** Verification is transitive trust: token → IdentityRegistry → TrustedIssuersRegistry → issuer's ClaimIssuer contract → issuer's off-chain key custody. The weakest link is usually the last hop, which is off-chain and outside the audit scope unless you put it in scope.

**Impact.** Total compliance bypass. Unqualified or sanctioned parties hold regulated securities. For the issuer this is not a hack writeup, it is a regulatory event.

**Mitigations.**
- Issuer signing keys in HSMs, rotation policy, and an on-chain revocation path that is actually tested.
- `TrustedIssuersRegistry` writes behind multisig + timelock; alerts on `TrustedIssuerAdded`.
- Scope issuer key custody into the audit or explicitly out of it in the report.

## 2. Claim forgery and replay

**What.** Claims are signatures over (identity, topic, data). Weak message construction lets a claim be replayed: same claim reused on another identity, another chain, another token ecosystem, or after revocation/expiry.

**Checklist of concrete failure modes.**
- Message omits the identity address → claim portable between identities.
- Message omits chain id → cross-chain replay for multi-chain deployments.
- `ecrecover` returning `address(0)` compared against an unset issuer slot → forged "signatures" validate.
- Validation checks the claim exists on the ONCHAINID but never calls the issuer's `isClaimValid` → revoked claims live forever.
- No expiry in the claim scheme → a 2024 KYC is still "valid" in 2030.

**Mitigations.** Bind claims to identity + topic + scheme, include expiry, check revocation at every verification, reject zero-address recovery, fuzz the validation path with malformed signatures.

## 3. Registry manipulation

**What.** Whoever can write to `IdentityRegistry`, `ClaimTopicsRegistry`, or `TrustedIssuersRegistry` can rewrite who is allowed to hold the token — without touching the token contract.

**Scenarios.**
- Remove a claim topic → verification requirements silently drop for all future checks.
- `registerIdentity` on an attacker wallet with a compromised registry-agent key → attacker is now a verified investor.
- `setIdentityRegistry` on the token swaps the entire eligibility set in one transaction.
- `deleteIdentity` on a victim → victim's tokens stranded (can hold, cannot send; cannot receive again).

**Mitigations.** Treat registry write-access like token admin access: multisig, timelock for structural changes, full event monitoring, and a documented governance policy for topic changes.

## 4. Compliance state desync

**What.** Stateful compliance modules (max balance, holder count, per-country caps) maintain internal accounting fed by `transferred()`, `created()`, `destroyed()` hooks. If any supply- or balance-changing path skips its hook, module state drifts from reality — permanently, because there is no reconciliation mechanism.

**How it plays out.** `forcedTransfer` skips `transferred()`. Module still thinks the sender holds the tokens. Sender tops up and now exceeds the module's recorded cap → all further transfers revert for that user, or the cap is effectively raised for the receiver. Either way the compliance guarantee is broken and support tickets look like random reverts.

**Paths that commonly forget hooks in forks:** `forcedTransfer`, `recoveryAddress`, `batchBurn`, migration/airdrop helper functions added by the fork.

**Mitigation.** Invariant test: for every module with storage, module-tracked totals must equal a value derivable from token balances after ANY sequence of operations. Run it under fuzzing (see [testing guide](test-guide/README.md)).

## 5. Malicious or buggy compliance modules

**What.** Modules are arbitrary code executed on every transfer. A buggy module reverts and DoSes the token; a malicious one approves anything, leaks information, or reenters.

**Details worth checking.**
- `canTransfer` making external calls to contracts that can be made to revert (oracle paused, dependency upgraded) → full-token DoS.
- Module removal requiring the module itself to not revert → malicious module resists removal.
- Unbounded module array → transfer gas grows until transfers exceed block gas limit.
- A module reading `msg.sender` assuming it's the token, when compliance can be bound/unbound to other tokens.

**Mitigations.** Audit every module as if it were the token. Keep modules small, view-only in `canTransfer`, and removable unilaterally by governance.

## 6. Agent privilege abuse

**What.** Agents can mint, burn, freeze, force-transfer, pause, and recover. Unlike DeFi admin keys, these powers map to *legal ownership of real assets*. A compromised agent key is equivalent to a court order in the attacker's favor.

**Aggravating factors specific to T-REX.**
- Agent operations typically still work while the token is paused — pausing does not contain a rogue agent.
- Agent role often exists on multiple contracts (token + registry); removing it in one place leaves power in the other.
- `forcedTransfer` only requires the receiver to be verified — a rogue agent can force-move assets to any verified wallet they control (getting one verified wallet is the only prerequisite, see vectors 1–3).

**Mitigations.** Multisig on all agent roles, separation between fast-path powers (freeze) and slow-path powers (registry/module changes, behind timelock), on-chain monitoring paging on every `forcedTransfer` and `RecoverySuccess`, and a documented incident-response runbook the issuer has actually rehearsed.

## 7. Recovery flow abuse

**What.** `recoveryAddress(lostWallet, newWallet, investorOnchainID)` exists so investors who lose keys don't lose legal ownership. Implemented loosely, it is a balance-theft primitive for agents.

**The core check that must exist:** the `investorOnchainID` passed by the agent must be verified to be the identity actually registered for `lostWallet`. If the function trusts the agent's parameters, an agent can pair any victim wallet with an attacker identity and drain it "legitimately."

**Secondary issues.** Frozen-token carryover undefined; old wallet left registered (dangling verified wallet); recovery working on wallets that were never registered; missing `RecoverySuccess` emission breaking monitoring.

## 8. Freeze accounting attacks

**What.** Partial freezes introduce a second balance ledger (`frozenTokens`) that must stay consistent with the ERC-20 ledger under every operation.

**Failure modes.**
- Spend paths checking `balanceOf` but not `balanceOf - frozenTokens` → frozen tokens spendable via that path (classically `transferFrom` or a batch variant).
- `burn`/`forcedTransfer` reducing balance below the frozen amount → invariant broken, later arithmetic underflows or permanently locks the account.
- Freeze more than balance allowed → account bricked with `frozenTokens > balanceOf`.
- Unfreeze logic in `forcedTransfer` emitting wrong amounts → compliance/monitoring sees a different ledger than reality.

**Invariant to test:** `frozenTokens[user] <= balanceOf(user)` after any operation sequence, and every spend path respects free balance.

## 9. Shared identity storage contamination

**What.** `IdentityRegistryStorage` is designed to be shared: several IdentityRegistries (several tokens) can bind to one storage so investors KYC once. That sharing is a blast-radius multiplier.

**Scenarios.** A compromised or buggy registry bound to shared storage can modify/delete identities relied on by every other token using that storage. `bindIdentityRegistry` with weak access control lets an attacker bind a hostile registry and write freely. Token A's operator deleting an identity "cleans up" token B's investor.

**Mitigations.** Bind/unbind strictly owner-gated, per-registry write scoping if forked, an inventory of every registry bound to shared storage (this inventory is an audit deliverable), and monitoring on bind events.

## 10. Implementation Authority takeover

**What.** Reference T-REX deployments use proxies whose implementations are resolved through a shared Implementation Authority, and suites are deployed via the TREX Factory. The Implementation Authority owner can change the implementation for every proxy that references it — every token, registry, and compliance deployed through it.

**Impact.** Single point of total compromise across all deployments sharing the authority. Strictly more powerful than any token-level role.

**Mitigations.** Treat Implementation Authority ownership as the crown jewels: strongest multisig in the org, timelock, upgrade events monitored externally, and for single-token issuers consider a dedicated (non-shared) authority to cut blast radius.

## 11. Transfer-path asymmetry

**What.** The same logical operation (moving tokens) exists in at least five code paths: `transfer`, `transferFrom`, `batchTransfer`, `forcedTransfer`, `recoveryAddress` (+ mint/burn as endpoints). Each fork edit to one path is a chance for the others to drift.

**Audit approach.** Build a matrix: rows = paths, columns = checks (paused, sender frozen, receiver frozen, free balance, receiver verified, canTransfer, hooks called, events). Fill it from code, not docs. Every empty cell is either a documented spec decision or a finding. This one table catches more T-REX bugs than any other single technique.

## 12. Launch misconfiguration

**What.** T-REX security is as much configuration as code. The suite can be deployed with correct code and still be wide open.

**Pre-launch checks.**
- ClaimTopicsRegistry non-empty (empty = everyone verified in common implementations).
- TrustedIssuersRegistry contains exactly the intended issuers, with correctly scoped topics.
- Compliance bound to token (`bindToken` called); intended modules added; module parameters (caps, lockups) set to production values, not test values.
- IdentityRegistry → correct storage; storage → bound back to registry.
- Agents/owners are the production multisigs, not the deployer EOA. Deployer EOA fully de-privileged.
- Pause state at launch matches the launch plan.
- All of the above verified on-chain post-deployment, not from the deploy script.

---

*Back to the [main checklist](README.md) · [Testing guide](test-guide/README.md)*

*Maintained by [QuillAudits](https://www.quillaudits.com). If your team is forking T-REX or launching an RWA token, [talk to our auditors](https://www.quillaudits.com/smart-contract-audit).*
