# CIS Benchmarks — local mirror + auto-sync

PDFs organized as `<Category>/<Technology>/<file>.pdf`, pulled from two sources:

- **portal** — `downloads.cisecurity.org` public download portal (current + the archives it still exposes).
- **workbench** — `workbench.cisecurity.org` full catalogue (every version and status, including legacy/EOL benchmarks such as RHEL 6, Windows 2003/2008, old ESXi, etc. that the public portal drops).

`cis_sync.py` fetches anything not already on disk (matched by filename), so repeated runs only grab new/updated benchmarks. Each run updates `report.md` and `state.json`.

## Secrets — read this first

The CIS sites have no download API key. Access rides on a **session cookie**, which *is* your login. **Never commit it.** A leaked cookie lets anyone act as you on `*.cisecurity.org` until it expires.

Get the cookies from a logged-in browser (DevTools → Application → Cookies):
- `downloads.cisecurity.org` → value of **`laravel_session`**
- `workbench.cisecurity.org` → value of **`workbench_session`**

Provide them one of two ways:

```bash
# A) environment variables (preferred)
export CIS_DOWNLOADS_SESSION='<laravel_session value>'
export CIS_WB_SESSION='<workbench_session value>'

# B) local file (git-ignored)
cp cis_config.example.json cis_config.json   # then paste values
```

Cookies expire (hours–days). When a run prints `session expired`, refresh the value. There is no clean way to automate the Auth0 login (SSO + MFA), so this stays a paste-the-cookie model.

## Run

```bash
python3 cis_sync.py                 # sync both sources once
python3 cis_sync.py --source portal # just the public portal
python3 cis_sync.py --dry-run       # show what would download
python3 cis_sync.py --loop 86400    # re-run daily (cron is usually better)
```

Zero dependencies (Python 3 standard library only).

## Scheduled on GitHub

`.github/workflows/sync.yml` runs weekly. Put the cookies in repo **Settings → Secrets and variables → Actions** as `CIS_DOWNLOADS_SESSION` and `CIS_WB_SESSION`. The workflow commits `report.md` and `state.json`; PDFs are git-ignored by default (multi-GB — use Git LFS or external storage if you want them tracked).
