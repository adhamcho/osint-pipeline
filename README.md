# OSINT Pipeline

OSINT correlation tool that prioritizes high-confidence signals and exposes conflicts across usernames, emails, and domains.

OSINT Pipeline is a local tool for collecting, normalizing, storing, and reviewing public-signal findings across multiple workflows. It is built around a simple idea:

- raw hits are noisy
- repeated signals are more useful
- conflicting signals should stay visible

The project is designed to help review leads, not to make identity claims.

## Why It Exists

Many OSINT tools are good at collecting data but weak at helping someone interpret it. They return long lists of hits, hide conflicts, and leave the analyst to manually decide what matters.

This project was built to make that review step easier by:

- normalizing different collectors into one finding model
- preserving source agreement and disagreement
- ranking stronger leads ahead of weaker ones
- reducing false positives in review-heavy workflows

In practice, this helps an analyst get to the strongest leads faster without manually sorting through dozens of conflicting or low-value results.

## What It Does

- runs multiple public-signal workflows
- normalizes collector output into one finding model
- stores runs and findings in SQLite
- generates readable Markdown reports
- supports combined case reports across username, email, full name, and domain inputs

## Workflows

### Core Workflows

#### Username

- Sherlock
- WhatsMyName
- source agreement and conflict reporting
- lead prioritization based on source agreement, platform strength, and correlation context

#### Email

- email domain analysis (`DNS`, `MX`, and service signals)
- Gravatar checks

#### Domain

- RDAP registration context
- DNS record collection

#### Case

- combines username, email, domain, and full-name context into one report
- highlights stronger leads first
- surfaces cross-signal overlaps and conflicts

### Optional Enrichments

- `Holehe`
  - adds email-level account-signal checks
  - useful when you want broader email account presence signals
- `HIBP`
  - adds breach history for email workflows
  - requires a paid API key for real email lookups
- `BuiltWith`
  - adds lightweight domain classification
  - useful for domain context, not identity proof

## Architecture

```text
collectors -> processors -> storage -> reports
```

Main layers:

- `collectors`: external lookups and integrations
- `processors`: normalization and status mapping
- `storage`: SQLite runs and findings
- `reports`: Markdown report generation

## Example Use

```powershell
.\run.bat case --username someuser --full-name "Some User" --email someone@example.com
```

This produces a combined report that helps review:

- public username findings
- email-related signals
- domain context if supplied
- overlaps and conflicts between workflows

The system highlights where sources agree and where they contradict, which helps keep weak evidence from looking stronger than it is.

## What A Good Lead Looks Like

Example case input:

```powershell
.\run.bat case --username exampleuser --full-name "Example User" --email exampleuser@gmail.com --include-holehe
```

Example output shape:

```text
Top Leads
- GitHub [high] (1 source found) | score=14
- Reddit [medium] (2 sources found) | score=13
- Spotify [medium] (single-source lead) | score=12

Cross-Signal Highlights
- Email local-part matches the provided username.
- Holehe / spotify lines up across email and username workflows.
```

Concrete example:

```text
Top Lead
- Platform: GitHub
- Status: Found
- Priority: High
- Reason: high-signal platform + public username match

Single-Source Lead
- Platform: Spotify
- Status: found by one workflow only
- Note: this is a useful lead, but it was not corroborated by another source
```

Why that matters:

- a high-signal platform like GitHub is easier to prioritize than a low-signal platform
- repeated findings across sources usually deserve more attention than single-source hits
- single-source leads stay weaker than corroborated ones, instead of being mistaken for confirmation
- cross-signal overlap is what makes a lead more interesting than a random hit

## How Scoring Works

Scores are review priorities, not identity scores.

Signals are ranked using source agreement, platform strength, and cross-workflow overlap.

In plain English:

- stronger platforms raise priority
  - for example, GitHub matters more than a low-signal platform
- repeated signals raise priority
  - multiple sources finding the same platform is more useful than one source alone
- cross-signal overlap raises priority
  - for example, email signals lining up with a username result
- unstable or not-yet-corroborated results reduce confidence
  - a single-source lead is still useful, but it should rank below corroborated findings

The goal is not to claim certainty. The goal is to help an analyst decide what to look at first.

## Quick Start

From the project root:

```powershell
.\run.bat
```

Or run workflows directly:

```powershell
.\run.bat run username someuser
```

```powershell
.\run.bat run email someone@example.com --include-holehe
```

```powershell
.\run.bat run domain example.com
```

## Example Output

- Sample case report: [`docs/examples/sample_case_report.md`](docs/examples/sample_case_report.md)

## Important Scope

- public-signal review tool
- not identity proof
- not a private-data collection tool
- not a reverse-people-finder

## Current Limitations

- public-signal availability can change between runs
- optional integrations may rate limit or return partial coverage
- different collectors vary in reliability and coverage
- results are meant to support analyst review, not prove identity


