# comanage-gitlab-connector

Synchronization tool between **COmanage** and **GitLab** that automates access provisioning.
The application reads groups defined in COmanage, optionally creates the corresponding hierarchy
in GitLab (groups and projects), applies roles according to the configured mapping, adds or updates
members, and removes absent users based on configurable policies.

## Key Features
- Discovers COmanage groups by prefix (e.g., `gl:`)
- Parses names in the format `gl:<project>:<repo>:<role>`
- Integrates with COmanage (Basic Auth) and GitLab (Personal Access Token)
- Automatically creates GitLab groups and projects (optional)
- Maps COmanage roles to GitLab access levels
- Fully reconciles membership (add/update/remove)
- Supports `dry_run` mode for safe simulation
- Keeps a pending list for users not yet found in GitLab

## Requirements
- Python 3.9+
- Access to a COmanage Registry via API (Basic Auth)
- A GitLab Personal Access Token with write permissions on groups/projects

## Installation
```bash
git clone https://github.com/luizakuze/comanage-gitlab-connector.git
cd comanage-gitlab-connector
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```


## Configuration
Modify the `config.yaml` file according to your environment and credentials.

### Configuration Notes
- `owner` (50) is automatically downgraded to `maintainer` (40) for projects.
- Set `verify_ssl: true` in production with valid certificates.

## Usage
You can run the synchronization once or keep it running continuously (default interval: 300 seconds):
```bash
python3 main.py
```

> Enable dry-run mode to preview actions without changes on config.yaml: <br> dry_run: true

## Logging
The connector logs every action:
- `[PARSE] 'gl:proj:repo:dev' -> path=proj/repo role=dev`
- `[OK] updated project proj/repo (id 123) <- user@example.org role 30`
- `[PENDING] user2@example.org not found in GitLab`

## Security Recommendations
- Never commit `config.yaml` or tokens.
- Use environment variables (`api_key_env`, `token_env`).
- Add to `.gitignore`:
    ```gitignore
    config.yaml
    pending.json
    .env
    .venv/
    __pycache__/
    ```