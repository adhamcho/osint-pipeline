# Sample Case Report

This is a sanitized example of the style and structure produced by the `case` workflow.

It is intentionally generic and is meant for documentation and showcase use, not as a real investigative result.

## Case Summary

- Username findings: `42`
- Email findings: `9`
- Domain findings: `1`
- High-signal username leads: `1`
- Medium-signal username leads: `3`
- Low-signal/noisy username results: `12`

## Overall Assessment

- Cross-signal correlation: `moderate`
- Lead quality: `moderate`
- Strongest overlap right now: `Spotify` aligns across email and username workflows.

## Key Findings

### Top Leads

- `GitHub` [high] (1 source found): `https://github.com/exampleuser` | `sherlock=found` | `score=14`
  - Why: name-token overlap in public URL: example (+2)
- `Reddit` [medium] (2 sources found): `https://www.reddit.com/user/exampleuser` | `sherlock=found, whatsmyname=found` | `score=13`
- `Spotify` [medium] (single-source lead): `https://open.spotify.com/user/exampleuser` | `sherlock=found, whatsmyname=not_found` | `score=12`
  - Why: email workflow found the same service (+3)

### Cross-Signal Highlights

- Email local-part matches the provided username.
- Holehe / spotify lines up across email and username workflows.

## Username Findings

- Top leads are shown above. This section highlights the next tier of username findings.
- `Instagram` [medium] (1 source found): `https://www.instagram.com/exampleuser/` | `whatsmyname=found` | `score=9`
- `YouTube` [medium] (1 source found): `https://www.youtube.com/@exampleuser` | `sherlock=found` | `score=9`
- Additional lower-priority username findings summarized: `9`

## Email Findings

### Assessment

- Account presence: `moderate` (2 positive account signal(s))
- Identity linkage: `limited` (common provider domain lowers domain-specific value)
- Reliability: `low-moderate` (rate limits reduce confidence in negative results)

### Summary

- Domain: `gmail.com`
- Common provider: `True`
- MX records found: `5`
- SPF records found: `1`
- DMARC record found: `yes`
- Gravatar profile found: `False`
- HIBP breaches found: `0`

### Account Signals

- Holehe services checked: `118`
- Holehe account signals found: `2`
- Holehe rate limited/errors: `76`
- Cross-signal overlaps with username results: `1`
- Strongest aligned services:
  - `Holehe / spotify`
- Additional email-only account signals: `1`
  - `Holehe / office365`

## Domain Findings

### Registration

- Domain: `example.com`
- Registrar: `Example Registrar`
- Created: `2020-01-01T00:00:00Z`
- Updated: `2026-01-01T00:00:00Z`
- Expires: `2027-01-01T00:00:00Z`

### DNS

- MX: `10 mail.example.com`
- TXT: `v=spf1 -all`

### BuiltWith Classification

- Classification: `likely CMS-backed site; broad web stack`

## Cross-Signal Correlation

- Email local-part matches the provided username.
- `Holehe / spotify`: Holehe found an email account signal and username workflow found `Spotify` for the provided username.
  - Public username review target: `https://open.spotify.com/user/exampleuser`

## Analyst Notes

- This report is a review aid, not identity proof.
- Signal strength and source agreement help prioritize leads, not confirm a person.
