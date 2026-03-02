# Versioned Docs Archive (Option 2 — Manual Subdirectory)

## Approach

When a release tag (e.g. `rfc-1`) is created, build the Sphinx docs at that tag
and commit the static HTML output to `docs/archive/<tag>/`. The CI workflow then
copies each archived version into the build output before uploading to Pages, so
`codygunton.github.io/pil2-proofman/<tag>/` stays live permanently even as the
main docs evolve.

## Adding a new archived version

```bash
# 1. Create an isolated worktree from the tag
git worktree add /tmp/docs-archive-rfc-1 rfc-1

# 2. Initialize the zisk submodule inside the worktree
git -C /tmp/docs-archive-rfc-1 submodule update --init docs/sphinx/zisk

# 3. Install Sphinx dependencies (skip if already installed)
pip install \
  'sphinx>=7.0' 'myst-parser>=3.0' 'sphinx-book-theme>=1.1' \
  'sphinx-copybutton>=0.5' 'sphinx-design>=0.6' \
  'sphinxcontrib-mermaid>=1.0' 'sphinx-autoapi>=3.7' \
  'numpy>=1.24.0'

# 4. Build the docs
sphinx-build -b html \
  /tmp/docs-archive-rfc-1/docs/sphinx \
  /tmp/docs-archive-rfc-1/docs/sphinx/_build/html

# 5. Copy the output into the main tree (exclude _modules/ — Rust viewcode is 34 MB,
#    links from the archive to Rust source pages will 404, which is acceptable)
mkdir -p docs/archive/rfc-1
cp -r /tmp/docs-archive-rfc-1/docs/sphinx/_build/html/. docs/archive/rfc-1/
rm -rf docs/archive/rfc-1/_modules

# 6. Clean up the worktree
git worktree remove /tmp/docs-archive-rfc-1

# 7. Commit (the archive directory is intentionally committed)
git add docs/archive/rfc-1
git commit -m "docs: archive rfc-1 Sphinx build"
```

## CI workflow change required

Add one step to `.github/workflows/docs.yaml` after `Build HTML` and before the
upload step:

```yaml
- name: Include archived versions
  run: |
    for dir in docs/archive/*/; do
      tag=$(basename "$dir")
      cp -r "$dir" docs/sphinx/_build/html/"$tag"
    done
```

This glob handles any future archives automatically — just repeat the steps above
for each new tag.

## Notes

- The built HTML is ~17 MB per version (excluding `_modules/`). Acceptable for a one-time archive.
- `docs/.gitignore` has a bare `index.html` rule. The `!archive/**/index.html` exception allows
  archive index files through. Without it, all directory URLs 404 (files like `genindex.html`
  still serve, but `/rfc-1/` itself does not). This exception is already in place; just be aware.
- Do NOT add `docs/archive/` to `.gitignore` — it must be committed.
- The archive is a snapshot of both the markdown prose and the autoapi Python
  source links at that exact tag.
- For a version picker in the UI, a hand-written `_static/versions.js` or a
  simple link in the index page is enough; no need for sphinx-multiversion.
