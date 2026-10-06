# Code signing policy

Free code signing provided by [SignPath.io](https://signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

## Scope

Official GeniaFirewall releases may sign only Windows PE files built from this repository:

- `GeniaFirewall.Service.exe`, the privileged WFP policy service;
- `GeniaFirewall.exe`, the portable UI containing the already signed Service payload.

No third-party or manually supplied executable is signed as a GeniaFirewall artifact.

## Build and release provenance

- Production signing is allowed only for a release commit reachable from `main` and identified by a release tag.
- The Service is built first on a GitHub-hosted Windows runner and submitted to SignPath with verified build origin.
- The signed Service is embedded into a fresh UI publish; the resulting UI is then submitted as a second signing request.
- The final portable ZIP contains only the signed `GeniaFirewall.exe`.
- SHA-256 is calculated after all signatures are applied and is published with the release.
- Both PE signatures and their timestamp chains must be verified before publication.

The signing certificate and private key are managed by SignPath Foundation. Private signing material is never stored in this repository or in a GitHub Actions secret.

## Team roles

GeniaFirewall is currently a single-maintainer project.

- Committer and reviewer: [GeniaSoftWin (`@geniasoftwin`)](https://github.com/geniasoftwin)
- Signing approver: [GeniaSoftWin (`@geniasoftwin`)](https://github.com/geniasoftwin)

External contributions require maintainer review before merge. Every production signing request requires an explicit manual approval in SignPath. These roles will be separated when another trusted maintainer joins the project.

## Security response

If a signing key, signing workflow, release artifact, or maintainer account is suspected of compromise, release signing is stopped immediately. The affected artifact is withdrawn, SignPath Foundation is notified, and certificate revocation is requested when appropriate. Security reports follow [`SECURITY.md`](SECURITY.md).

Runtime data handling is documented in [`PRIVACY.md`](PRIVACY.md).
