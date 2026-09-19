# Contributing

GeniaFirewall is a security-sensitive Windows application. Keep changes focused and explain their security and compatibility impact.

Before opening a pull request:

1. Build the solution in Release mode for `win-x64`.
2. Run the lifecycle, policy, TUN, and diagnostics gates in `RELEASE_CHECKLIST_0.7.3-STABLE_RU.md` when the change can affect them.
3. Do not commit binaries, publish output, logs, profiles, credentials, personal paths, or captured network data.
4. Document any change to IPC, WFP filters, service privileges, persistence, installation, or cleanup behavior.

Security vulnerabilities must be reported privately according to `SECURITY.md`, not through a public pull request or issue.
