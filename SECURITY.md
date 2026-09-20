# Security Policy

## Scope

This tool decrypts and lifts ionCube-encoded PHP files offline. It is built
for recovering source you own or are licensed to modify: lost source, vendor
abandonment, license-compliant internal maintenance. The loader is never
executed; all decoding is static analysis of the file formats.

Do not use it to break license terms or access code you have no right to
read. You are responsible for complying with the law and with the license
attached to any file you process.

## Reporting

For vulnerabilities in this repository (not in the ionCube Loader itself),
open a private security advisory via GitHub, or email the maintainer listed
in the git history. Include a reproduction: input file, command, observed
versus expected behavior.

Reports about ionCube Loader vulnerabilities belong with ionCube Ltd, not
here. This project publishes no loader exploits; it documents format parsing
recovered from an authorized research engagement.
