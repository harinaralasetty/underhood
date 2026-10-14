# Security policy

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/harinaralasetty/underhood/security/advisories/new), when enabled for the published repository. Do not post sensitive input files in public issues.

Relevant issues include parser crashes, unbounded resource use, unintended file access or writes, and misleading evidence. Include a minimal synthetic reproducer, tool version, host OS and expected behavior.

Underhood never executes inputs. Its parsers still process untrusted bytes. Inspect a stable copy of a target: concurrent filesystem mutation is outside the portable path-checking guarantee. Signature parsing does not establish authenticity or trust.
