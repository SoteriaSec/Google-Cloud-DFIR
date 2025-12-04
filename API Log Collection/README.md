# GCP Log Collector

`gcp_log_collector.py` is a Python tool for incident response and threat hunting on Google Cloud Logging.

It uses **OAuth2 (user consent)** rather than service accounts, so you can safely publish this script and each user can run it with **their own Google account and permissions**.

The tool supports:

- Listing projects a user can see (no log access required).
- Listing log buckets in a project (and optionally their views).
- Collecting logs from **all buckets** in a project.
- Collecting logs from a **specific log bucket** in a project.
- Restricting collection to a specific **time window** (ISO 8601 / RFC3339, to the second).
- Adding an extra **Cloud Logging filter** on top of the time range.
- Writing logs as **JSON Lines**:
  - A single file or stdout (default),
  - Split **per day**, or
  - Split **per bucket**.
- Checking access to **private log views** before collecting.

This README walks through the full setup process (Google Cloud configuration + script usage) so others can set up their own accounts correctly.

---

## Step 1 – Requirements

- Python **3.9+**
- `pip` for installing dependencies.
- A Google account with access to at least one Google Cloud project.
- For each user:
  - Their own **OAuth 2.0 “Desktop app” client** (JSON file).
  - Appropriate IAM permissions in any project(s) whose logs they want to read.

### Python dependencies

A `requirements.txt` is included in this repository. Install dependencies with:

```bash
pip install -r requirements.txt
```
OR
```bash
pip3 install -r requirements.txt
```

This will install:

- `google-auth`
- `google-auth-oauthlib`
- `google-api-python-client`

---

## Step 2 – Repository contents and ignoring secrets

Typical files in the repo:

- `gcp_log_collector.py` – main script.
- `README.md` – this documentation.
- `requirements.txt` – Python dependencies.

---

## Step 3 – Enable required Google Cloud APIs

In the Google Cloud project where you will create your OAuth client:

1. Open the Google Cloud Console.
2. Go to **APIs & Services → Library**.
3. Enable the following APIs:
   - **Cloud Logging API** (`logging.googleapis.com`)
      - _It's common for this to already be enabled_
   - **Cloud Resource Manager API** (`cloudresourcemanager.googleapis.com`)

These allow the script to:

- List projects (`list-projects`), and  
- Read log buckets and entries (`list-buckets`, `collect-logs`).

---

## Step 4 – Configure the OAuth consent screen

Still in the same Google Cloud project:

1. Go to **APIs & Services → OAuth consent screen**.
2. Select a **User type**:
   - **External** if you want to allow sign-in from accounts outside your organisation.
   - **Internal** if you only want to allow accounts within your Google Workspace.
3. Provide the required information:
   - App name (for example, `GCP Log Collector`),
   - Support email,
   - Developer contact details, and any other required fields.
4. You do **not** need to manually add scopes here; the script will request:
   - `https://www.googleapis.com/auth/cloud-platform.read-only`

Save and publish the consent screen as required.

---

## Step 5 – Create an OAuth 2.0 client (Desktop app)

Each person running the script should create **their own** OAuth client and download the JSON file.

1. Go to **APIs & Services → Clients**.
2. Click **Create client**.
3. For **Application type**, select **Desktop app**.
4. Give it a name (for example, `IR Log Collector`).
5. Click **Create**.
6. Click **Download JSON** for this client.
7. Save the file as `client_secret.json` **in the same directory** as `gcp_log_collector.py`, or store it elsewhere and reference it with `--credentials-file`.

Example layout:

```text
.
├── gcp_log_collector.py
├── README.md
├── requirements.txt
└── client_secret.json        # YOUR file (not committed)
```

> Never store your `client_secret.json` in any public places, like GitHub repositories ;) .

You can also point the script to the file explicitly:

```bash
python gcp_log_collector.py   --credentials-file /path/to/your_client_secret.json   list-projects
```

Or via an environment variable:

```bash
export GCP_OAUTH_CLIENT_SECRETS=/path/to/your_client_secret.json
python gcp_log_collector.py list-projects
```

---

## Step 6 – Set up permissions in log-source projects

The script uses your **user identity** to call APIs.  
In any project whose logs you want to read, your account must have:

1. **Project visibility** (to list the project):

   - A role such as `roles/viewer`, or
   - Any role that includes `resourcemanager.projects.get`.

2. **Logging read access** (to read log entries and views):

   - A role such as `roles/logging.viewer` on that project, or
   - Another custom/combined role that includes:
     - `logging.logEntries.list`, and
     - `logging.views.access` (for views, including private log views).

As a rough rule: if you can view logs in the Cloud Console’s **Logs Explorer** for that project, you’re likely to have the right permissions for this script as well.

---

## Step 7 – First run and token handling

When you run the tool for the first time, it will:

1. Read your `client_secret.json`.
2. Launch a browser window with the OAuth consent screen.
3. Ask you to sign in and approve access.
4. Create a `token.json` file in the current directory (or wherever `--token-file` points).

Example:

```bash
python gcp_log_collector.py list-projects
```

After approving access, you’ll see your projects listed, and a `token.json` file will appear beside the script.

Notes:

- `token.json` contains your OAuth refresh token and access tokens.
- It is **user-specific**; do not share it with others.
- If you delete `token.json`, the next run will prompt for OAuth again.

You can configure token location explicitly:

```bash
python gcp_log_collector.py   --credentials-file client_secret.json   --token-file ~/.config/gcp-log-collector/token.json   list-projects
```

Or via environment:

```bash
export GCP_OAUTH_TOKEN_FILE=~/.config/gcp-log-collector/token.json
python gcp_log_collector.py list-projects
```

---

## Step 8 – Global CLI options and basic commands

All commands share some global flags:

```bash
python gcp_log_collector.py   --credentials-file client_secret.json   --token-file token.json   --log-level INFO   <command> ...
```

- `--credentials-file` – path to your OAuth client JSON.
- `--token-file` – path to your OAuth token cache.
- `--log-level` – one of `DEBUG`, `INFO`, `WARNING`, `ERROR` (default `INFO`).

The main subcommands are:

- `list-projects`
- `list-buckets`
- `collect-logs`

### 8.1 – List projects (no logs involved)

```bash
python gcp_log_collector.py list-projects
```

Example output:

```text
PROJECT_ID      PROJECT_NAME                     DISPLAY_NAME        STATE
my-ir-project   projects/123456789012            IR Project          ACTIVE
sec-prod        projects/987654321000            Security Prod       ACTIVE
```

This uses the **Cloud Resource Manager API** only; it does not access any logs.

### 8.2 – List log buckets and views

List log buckets in a given project:

```bash
python gcp_log_collector.py list-buckets --project-id my-ir-project
```

Example:

```text
BUCKET_ID   LOCATION  FULL_NAME                                                       RETENTION_DAYS  LIFECYCLE_STATE
_default    global    projects/my-ir-project/locations/global/buckets/_default       30              ACTIVE
sec-logs    global    projects/my-ir-project/locations/global/buckets/sec-logs       365             ACTIVE
audit-logs  global    projects/my-ir-project/locations/global/buckets/audit-logs     400             ACTIVE
```

Include views for each bucket:

```bash
python gcp_log_collector.py list-buckets   --project-id my-ir-project   --show-views
```

Example snippet:

```text
sec-logs  global  projects/my-ir-project/locations/global/buckets/sec-logs  365  ACTIVE
  VIEW  _AllLogs      projects/my-ir-project/locations/global/buckets/sec-logs/views/_AllLogs      Default view
  VIEW  ir-private    projects/my-ir-project/locations/global/buckets/sec-logs/views/ir-private    Restricted IR view
```

You will use these `BUCKET_ID` values (for example, `sec-logs`) with the `--bucket` flag in `collect-logs`.

---

## Step 9 – Collecting logs

All log collection is done with the `collect-logs` subcommand.

### 9.1 – Time format

- `--start-time` and `--end-time` are RFC3339 / ISO 8601 timestamps, for example:
  - `2025-11-01T00:00:00Z`
  - `2025-11-02T23:59:59Z`
- These map to the `timestamp` field in Cloud Logging:
  - `timestamp >= "<start-time>"`
  - `timestamp <= "<end-time>"`

You may omit one or both, but beware that omitting both will attempt to return **all retained logs** in scope.

---

### 9.2 – Default output: single file or stdout

By default, the script writes all logs to a **single output stream**:

- If `--output` is provided → one JSON Lines file.
- If `--output` is omitted → stdout.

Each line is a single JSON log entry.

---

### 9.3 – Collect logs from all buckets in a project

To collect from **all log buckets** in a project within a time window:

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --start-time 2025-11-01T00:00:00Z   --end-time   2025-11-02T00:00:00Z   --output my_ir_logs.jsonl
```

This uses:

- `resourceNames = ["projects/my-ir-project"]`, which fans out across all buckets for that project.

If you omit the time range entirely, it will attempt to stream all logs retained:

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --output all_logs.jsonl
```

Use this with care, especially in high-volume environments.

---

### 9.4 – Collect logs from a specific bucket

First, identify the bucket using `list-buckets`.  
Example bucket resource:

```text
projects/my-ir-project/locations/global/buckets/sec-logs
         └── project          └─ location           └─ BUCKET_ID (short name)
```

To collect only from this bucket:

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --bucket sec-logs   --start-time 2025-11-01T00:00:00Z   --end-time   2025-11-02T23:59:59Z   --output sec_logs.jsonl
```

The script:

1. Resolves `sec-logs` to its full name.
2. Queries via the `_AllLogs` view for that bucket.

---

### 9.5 – Apply an additional Cloud Logging filter

Use the `--filter` flag to add extra Logging filter conditions, which are **AND-ed** with the time range.

For example, only collect entries with `severity >= ERROR` from Cloud Audit logs:

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --start-time 2025-11-01T00:00:00Z   --end-time   2025-11-02T00:00:00Z   --filter 'severity >= ERROR AND logName:"cloudaudit.googleapis.com%2Factivity"'   --output error_audit.jsonl
```

Internally this becomes:

```text
(timestamp >= "..." AND timestamp <= "...") AND (severity >= ERROR AND ...)
```

You can use any valid Cloud Logging filter here, including:

- `logName:` clauses,
- `resource.type="gce_instance"`, etc,
- label filters,
- text search with `textPayload:"string"` or `jsonPayload.field:"string"`.

---

### 9.6 – Split output per day

If you want one file per calendar date (based on each entry’s `timestamp` field), use `--split-mode per-day`:

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --start-time 2025-11-01T00:00:00Z   --end-time   2025-11-05T23:59:59Z   --split-mode per-day   --output-dir my_ir_logs_per_day
```

This creates files like:

- `my_ir_logs_per_day/2025-11-01.jsonl`
- `my_ir_logs_per_day/2025-11-02.jsonl`
- …

Notes:

- If `--output-dir` is omitted, the default directory is `logs_per_day/`.
- `--output` is **ignored** when `--split-mode` is not `none`.
- Entries with no or invalid timestamps go into special files such as:
  - `no-timestamp.jsonl`
  - `invalid-timestamp.jsonl`

---

### 9.7 – Split output per bucket

To produce **one file per bucket**:

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --split-mode per-bucket   --output-dir my_ir_logs_per_bucket
```

The script will:

1. List all buckets in the project.
2. Query logs from each bucket (via its `_AllLogs` view).
3. Write a file per bucket, for example:

   - `my_ir_logs_per_bucket/_default.jsonl`
   - `my_ir_logs_per_bucket/sec-logs.jsonl`
   - `my_ir_logs_per_bucket/audit-logs.jsonl`

If you use `--split-mode per-bucket` without specifying `--output-dir`, it defaults to:

```text
logs_per_bucket/
```

You can also combine this with `--bucket` to export just a single bucket into its own file:

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --bucket sec-logs   --split-mode per-bucket   --output-dir my_ir_logs_per_bucket
# → my_ir_logs_per_bucket/sec-logs.jsonl
```

---

### 9.8 – Check private log view access

If your environment uses **private log views** for sensitive data, you may want to confirm that your current identity can read those views before relying on them.

Use the `--check-private-views` flag with `collect-logs`.

#### Check all buckets in a project

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --check-private-views   --start-time 2025-11-01T00:00:00Z   --end-time   2025-11-01T23:59:59Z   --output my_ir_logs.jsonl
```

Before collecting, the script prints a table such as:

```text
BUCKET_ID   VIEW_ID         STATUS      NOTE
_default    _AllLogs        OK          view readable
sec-logs    _AllLogs        OK          view readable
sec-logs    ir-private      NO_ACCESS   HTTP 403: <...>
audit-logs  _AllLogs        OK          view readable
```

- `OK` – the view is readable with your current permissions.
- `NO_ACCESS` – a 403/404 was returned; you do not have access.
- `ERROR` – some other HTTP error occurred.

The script **still proceeds to collect logs**, using the normal scopes (for example `_AllLogs`), even if some private views are not accessible. This check is informational so you can fix IAM before relying on private views.

#### Check views for a specific bucket only

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --bucket sec-logs   --check-private-views   --output sec_logs.jsonl
```

Only views on `sec-logs` are checked.

---

## Step 10 – Quick reference – common commands

### Install dependencies

```bash
pip install -r requirements.txt
```

### First run (authenticate and list projects)

```bash
python gcp_log_collector.py list-projects
```

### Discover buckets and views

```bash
python gcp_log_collector.py list-buckets --project-id my-ir-project
python gcp_log_collector.py list-buckets --project-id my-ir-project --show-views
```

### Collect all logs in a project into one file

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --start-time 2025-11-01T00:00:00Z   --end-time   2025-11-02T00:00:00Z   --output my_ir_logs.jsonl
```

### Collect logs from one bucket only

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --bucket sec-logs   --start-time 2025-11-01T00:00:00Z   --end-time   2025-11-02T23:59:59Z   --output sec_logs.jsonl
```

### Collect with an extra Logging filter

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --filter 'severity >= ERROR AND logName:"cloudaudit.googleapis.com%2Factivity"'   --output error_audit.jsonl
```

### Split output per day

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --split-mode per-day   --output-dir my_ir_logs_per_day
```

### Split output per bucket

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --split-mode per-bucket   --output-dir my_ir_logs_per_bucket
```

### Check private views before collecting

```bash
python gcp_log_collector.py collect-logs   --project-id my-ir-project   --check-private-views   --output my_ir_logs.jsonl
```

---

## Step 11 – Security notes and best practice

- The script uses **OAuth2 user credentials**, not service accounts. It therefore acts with **your** permissions in each project.
- Treat the following files as sensitive:
  - `client_secret.json` – never commit it to source control or share it.
  - `token.json` – contains refresh tokens; do not share it.
- Use **least privilege**:
  - Grant only the roles required to read the logs you need.
  - Consider using **private log views** to limit who can see specific log data, and use `--check-private-views` to verify access.
- For investigations, store exported logs in secure storage appropriate for your organisation’s policies (for example, encrypted storage, restricted access shares).

---

## Step 12 – Contributing

If you’d like to extend this tool, some ideas:

Pull requests and issues are welcome.
