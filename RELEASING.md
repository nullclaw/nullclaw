# Releasing

NullClaw uses [CalVer](https://calver.org/) with the format `YYYY.M.D` (e.g., `v2026.3.12`).

Pushing a tag matching `v*` to `main` triggers the [Release workflow](.github/workflows/release.yml), which builds binaries for all supported platforms and publishes a GitHub Release.

## Steps

1. **Checkout and update `main`**

   ```bash
   git checkout main
   git pull origin main
   ```

2. **Create a release branch**

   ```bash
   git checkout -b release/vYYYY.M.D
   ```

3. **Bump the version in `build.zig.zon`**

   Update the `.version` field to match today's date:

   ```diff
   - .version = "2026.3.11",
   + .version = "2026.3.12",
   ```

4. **Commit the version bump**

   ```bash
   git add build.zig.zon
   git commit -m "vYYYY.M.D"
   ```

5. **Push the branch and create a PR**

   ```bash
   git push origin release/vYYYY.M.D
   gh pr create --title "vYYYY.M.D" --body "Version bump for vYYYY.M.D release."
   ```

6. **Merge the PR** (or get it reviewed and merged)

7. **Tag the release on `main`**

   ```bash
   git checkout main
   git pull origin main
   git tag vYYYY.M.D
   git push origin vYYYY.M.D
   ```

   The tag push triggers CI, which builds and publishes the release automatically.

## Notes

- The tag **must** be pushed to `main` — tagging a feature branch won't produce a release.
- If multiple releases happen on the same day, append a patch number (e.g., `v2026.3.12.1`), though this should be rare.
- NullHub follows the same versioning and release process. Both repos should be released together with matching version numbers.
