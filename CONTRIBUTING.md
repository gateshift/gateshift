# Contributing to Gateshift

Thank you for caring enough to read this. Gateshift takes a deliberate,
slightly unusual position on contributions, and this page explains it
honestly rather than burying it in legalese.

## Issues are the contribution channel

**Bug reports are the most valuable thing you can send.** Vendors rename
fields and change response schemas between firmware releases, and no lab
covers every version of every supported vendor. A good report contains:

1. the **vendor and exact firmware/management version**,
2. the **verbatim** error or drop-report line, and
3. what the documentation led you to expect instead.

A bug is when Gateshift does not do what the documentation says. Deliberate
boundaries live in `KNOWN_LIMITATIONS.md` - anything beyond those is a
feature request.

**Feature requests are welcome from anyone.** They are read and labeled,
but they carry no commitment or date. Enterprise subscribers get a say in
release prioritization.

## Pull requests are not accepted as a rule

This is a single-copyright codebase, and that is what makes its model
possible: the Community Edition is licensed under the Business Source
License with a guaranteed conversion to MPL 2.0 per release, and the
Enterprise Edition ships under a commercial agreement. Both require the
licensor to own the code outright. A single merged foreign line would
compromise, for that line, both the right to ship it commercially and the
right to relicense it at the change date.

For the common case this costs you nothing: **describe the vendor quirk in
an issue and it gets fixed.** The information - which endpoint, which
version, which error - is the valuable part; the patch is usually the easy
part on this side.

**Substantial contributions are possible case by case.** If you want to
build something bigger - a parser, a vendor driver - open an issue first.
Accepting it requires a contributor agreement that assigns the necessary
rights; that is an open door, not a formality we enjoy.

## Security

Never report vulnerabilities in a public issue - see [SECURITY.md](SECURITY.md).

## Support expectations

There is no support entitlement for the Community Edition. Issues that are
documented limitations or usage questions are closed with a pointer, quickly
and without ceremony. That keeps maintainer time on defects, which benefits
everyone running the tool.
