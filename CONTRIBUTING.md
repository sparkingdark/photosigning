# Contributing to PhotoSigning

Contributions can include bug fixes, documentation, accessible interface improvements,
test cases, and clearer verification results. Start with a focused change that others
can reproduce and review. Be respectful in issues, reviews, and discussions.

## Before you start

Read the [README](README.md) and [user guide](docs/user-guide.md). For changes to
signing, watermarking, or matching, also read the
[technical reference](docs/technical-reference.md).

Search [existing issues](https://github.com/sparkingdark/photosigning/issues) and
[pull requests](https://github.com/sparkingdark/photosigning/pulls) before opening
another. Discuss major features, new dependencies, changes to signed formats, or
changes to verification thresholds in an issue before implementing them. Small
fixes and documentation improvements can go straight to a pull request.

## Development setup

Use Python 3.11 or newer and [uv](https://docs.astral.sh/uv/getting-started/installation/).
Fork the repository on GitHub, then replace `YOUR_USERNAME` below with your account:

```bash
git clone https://github.com/YOUR_USERNAME/photosigning.git
cd photosigning
git remote add upstream https://github.com/sparkingdark/photosigning.git
git switch -c describe-your-change
uv sync --locked --group dev
uv run streamlit run app.py
```

Open **http://localhost:8501** and use the demo landscape for manual checks.
TrustMark and some tests download model weights on first use; allow network access
for that download. Subsequent model inference runs locally on the CPU. Full image
and UI checks take more resources than the core signature tests.

Use test keys and synthetic images. Keep personal photos, private-key backups,
registry databases, `.env` files, and `.streamlit/secrets.toml` out of commits and
issue attachments. To isolate a manual experiment, set `PHOTOSIGNING_REGISTRY` to
a disposable SQLite path; automated registry tests use temporary paths.

## Project layout

| Path | Responsibility |
| --- | --- |
| `app.py` | Streamlit interface and session interactions. |
| `photosigning/core.py` | Exact pixel signatures, keys, and image validation. |
| `photosigning/content_credentials.py` | C2PA embedding, verification, and certificates. |
| `photosigning/trustmark_image.py` | TrustMark embedding and tag recovery. |
| `photosigning/majik_image.py` | Legacy DCT watermark adapted from Majik Signature. |
| `photosigning/registry.py` | Signed records, SQLite storage, and visual matching. |
| `photosigning/workflow.py` | Combined signing and inspection workflows. |
| `photosigning/audit.py` | Reproducible transformation and adversarial checks. |
| `tests/` | Core, C2PA, resilience, and Streamlit tests. |
| `docs/` | User and technical guides, audit reports, and publication review. |

## Checks

Run Ruff and the tests relevant to your change from the repository root:

```bash
uv run ruff check .
uv run pytest -q tests/test_core.py
```

Choose test modules based on the behavior changed:

| Test module | Coverage |
| --- | --- |
| `tests/test_core.py` | Exact signatures, key backups, input validation, and tampering. |
| `tests/test_content_credentials.py` | C2PA signing, certificate handling, and validation. |
| `tests/test_resilience.py` | Legacy watermark recovery, registry records, and matching. |
| `tests/test_maximum_resilience.py` | TrustMark exports, transformed images, and copied-tag rejection. |
| `tests/test_app.py` | Streamlit navigation and signing/verification workflows. |

For changes to signing, verification, the registry, or the interface, run the full
suite before submitting and include the result in your pull request:

```bash
uv run pytest -q
```

For documentation-only changes, verify links, examples, and consistency with the
current code; an application test run is not necessary. Do not claim checks you
did not run. Describe any failed or unavailable checks so reviewers can assess them.

For changes affecting image recovery or forgery resistance, run the reproducible
audit as well. Use a temporary output directory while experimenting:

```bash
uv run python -m photosigning.audit --output /tmp/photosigning-audit
```

On Windows, replace `/tmp/photosigning-audit` with a path in your temporary
directory. The command writes Markdown and JSON reports. Include relevant results,
including failures. Update the committed reports in `docs/` only when intentionally
refreshing the documented baseline, and explain the environment and behavior changes.

## Code and behavior expectations

- Follow the surrounding Python style and Ruff configuration in `pyproject.toml`
  (100-character line length). Avoid unrelated formatting changes.
- Add a focused regression test for a bug or changed behavior. Prefer deterministic
  synthetic images and temporary registries to downloaded or personal photos.
- Preserve the distinction between exact integrity, signer trust, and approximate
  image recognition. A visual match must not be reported as an unchanged image or
  proof of ownership.
- Keep signature validation, input bounds, and export self-checks intact. Discuss
  changes to canonical serialization, format versions, or matching thresholds;
  explain compatibility with existing images and exported records.
- Document new behavior and limitations. Robustness claims should identify the
  transformations and inputs tested, including cases that failed.
- When dependencies change, update `pyproject.toml` and `uv.lock` with `uv lock`,
  review the resulting diff, and update relevant third-party licensing information.

## Report a bug or propose a feature

For a bug, include the expected result, actual result, steps to reproduce, Python
and operating-system versions, and the commit or release you used. Include a
sanitized traceback if available. For watermarking or matching bugs, identify the
protection method, image dimensions, transformation settings, and whether the
matching registry record was available. Prefer a reproduction using the demo image.

For a feature, describe the use case, proposed behavior, and how it fits the app's
local workflow. Explain any effect on privacy, compatibility, or dependencies.

For a security vulnerability, use **Security → Report a vulnerability** if private
reporting is enabled on the repository. If it is unavailable, open a minimal issue
requesting a private contact method without including exploit details, keys, or
private images.

## Submit a pull request

1. Keep the pull request focused on one problem or feature.
2. Review `git diff` and `git status` before committing; exclude generated model
   weights, databases, credentials, build output, and unrelated changes.
3. Commit the change with a descriptive message and push your branch to your fork.
4. Open a pull request against the upstream default branch. Explain the problem,
   resulting behavior, related issue, checks run, and any compatibility implications.
   For interface changes, attach a screenshot using synthetic data if it helps review.
5. Respond to review feedback and rerun affected checks after substantive changes.

## Licensing and source attribution

Submit only material you have the right to contribute. Contributions to this
project are submitted under its [Apache-2.0 license](LICENSE). Disclose any
third-party source, asset, model, or dependency and preserve its applicable notices;
do not assume PhotoSigning's license replaces another project's license.

For changes derived from Majik Signature, preserve its copyright and license notice
and update [the modification summary](third_party/majik-signature/NOTICE.md).
See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for other dependencies and assets.

If you use AI-assisted tools, you remain responsible for reviewing the contribution,
testing its behavior, and identifying and retaining any known third-party attribution.
