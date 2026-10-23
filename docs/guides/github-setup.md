# GitHub Repository Setup

This document explains how to connect this local Fluxheim folder to a GitHub
repository that already contains placeholder files such as `.gitignore`,
`README.md`, and `LICENSE`.

## Before Connecting

From the Fluxheim folder:

```bash
git status --short
git remote -v
```

If the project is not initialized yet:

```bash
git init
git branch -M main
```

Fluxheim should keep `LICENSE` as `EUPL-1.2`. If the GitHub repository already
has a different license file, decide before merging which license is
authoritative.

## Recommended Safe Path

Use this when the remote has files you do not want to accidentally overwrite.

1. Add the GitHub remote:

```bash
git remote add origin git@github.com:OWNER/fluxheim.git
```

or with HTTPS:

```bash
git remote add origin https://github.com/OWNER/fluxheim.git
```

2. Fetch the remote:

```bash
git fetch origin
```

3. Inspect what is already on GitHub:

```bash
git ls-tree --name-only origin/main
git show origin/main:README.md
git show origin/main:LICENSE
git show origin/main:.gitignore
```

If the branch is named `master` remotely, use `origin/master` in those commands
or rename the remote branch in GitHub before continuing.

4. Create a local integration branch:

```bash
git switch -c integrate-github-main
```

5. Merge the remote history:

```bash
git merge origin/main --allow-unrelated-histories
```

6. Resolve conflicts deliberately:

- keep Fluxheim's README if the remote README is empty;
- keep the EUPL-1.2 LICENSE;
- merge `.gitignore` entries if the remote has useful ignore patterns;
- do not delete Fluxheim docs or source files.

7. Run checks:

```bash
scripts/release_checks.sh
```

8. Commit the integration:

```bash
git add .
git commit -m "Import Fluxheim project"
```

9. Push:

```bash
git push -u origin integrate-github-main
```

Open a pull request from `integrate-github-main` to `main`, or push to `main`
after reviewing the diff.

## Fast Path For Empty Placeholder Repositories

Use this only if the remote files are truly empty/placeholders and you are
comfortable replacing them with the local Fluxheim project.

```bash
git remote add origin git@github.com:OWNER/fluxheim.git
git fetch origin
git push --force-with-lease -u origin main
```

`--force-with-lease` is safer than plain `--force` because it refuses to
overwrite new remote commits you have not fetched.

## If The Local Branch Is Not Main

Check the current branch:

```bash
git branch --show-current
```

Rename it to `main`:

```bash
git branch -M main
```

Then push:

```bash
git push -u origin main
```

## If The Remote Already Exists

If `origin` is already configured:

```bash
git remote -v
```

Change it with:

```bash
git remote set-url origin git@github.com:OWNER/fluxheim.git
```

## What To Commit Before Publishing

Before the first GitHub push, the repository should include:

- `Cargo.toml` and `Cargo.lock`;
- `rust-toolchain.toml`;
- `deny.toml`;
- `README.md`;
- `CHANGELOG.md`;
- `ROADMAP.md`;
- `SECURITY.md`;
- `LICENSE`;
- `docs/`;
- `examples/`;
- `scripts/`;
- `src/`;
- `.github/workflows/ci.yml`;
- `.github/dependabot.yml`;
- `Containerfile`;
- `.containerignore`;
- `.cargo/` config if it contains project-specific build settings.

Do not commit local secrets, private TLS keys, ACME account keys, Cloudflare API
tokens, cache directories, Podman volumes, or generated release artifacts.

## GitHub Security Settings

After pushing, confirm these repository settings are enabled:

- Dependabot alerts;
- Dependabot version updates from `.github/dependabot.yml`;
- CodeQL default setup for code scanning alerts;
- private vulnerability reporting or GitHub security advisories.

Keep only one active CodeQL configuration. If GitHub default setup is enabled,
do not also add an advanced CodeQL workflow; GitHub rejects the duplicate SARIF
upload.

## First Tag After GitHub Import

After the repository is on GitHub and checks pass, create a signed incubator
tag instead of jumping straight to 1.0:

```bash
git tag -s v0.1.0 -m "Fluxheim 0.1.0 repository baseline"
git tag -v v0.1.0
git push origin v0.1.0
```

Use the versioning plan to decide when the project is ready for `v1.0.0`.
