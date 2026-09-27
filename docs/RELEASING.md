# Releasing MapacheSPIM

Releases are published to [PyPI](https://pypi.org/project/mapachespim/) by the
[Release workflow](../.github/workflows/release.yml) when a GitHub release is published. It uses
PyPI *trusted publishing*, so no API token is stored in the repository.

## One-time setup

1. Create an account on [pypi.org](https://pypi.org/) (enable two-factor authentication).
2. Add a *pending publisher* for the project, since it does not exist on PyPI yet: go to
   **Your account > Publishing > Add a new pending publisher** and enter
   - PyPI project name: `mapachespim`
   - Owner: `UCSBarchlab`
   - Repository name: `MapacheSPIM`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. In the GitHub repository, create an environment named `pypi`
   (**Settings > Environments > New environment**). Optionally require a reviewer so every
   release needs an approval before it is uploaded.

After the first release, the pending publisher becomes a normal trusted publisher for the project.

## Making a release

1. Make sure CI is green on `main`.
2. Update the version in `pyproject.toml` and `mapachespim/__init__.py` (they must match), and move
   the "Unreleased" notes in `CHANGELOG.md` under the new version. Commit and push.
3. If any toolchain change affects code generation, rebuild the example binaries with
   `make -C examples DEBUG=1` and commit them.
4. On GitHub, create a release with a tag named `v<version>` (for example `v0.3.0`) and publish it.
   The workflow checks the tag matches `pyproject.toml`, builds the sdist and wheel, and uploads
   them.

Once published, students can install with:

```bash
pipx install mapachespim
```

At that point, update the install instructions in `README.md` and `docs/user/quick-start.md` to use
the PyPI name instead of the `git+https://` URL.
