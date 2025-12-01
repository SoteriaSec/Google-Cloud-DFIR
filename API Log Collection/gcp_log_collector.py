#!/usr/bin/env python3
"""
gcp_log_collector.py

Cloud Logging IR helper that authenticates with OAuth2 and can:

- List projects the authenticated user can see (no log access required).
- List log buckets in a project (and optionally their views).
- Collect logs from:
    * All log buckets in a project, or
    * A specific log bucket in a project.
- Filter logs by a time range (ISO8601/RFC3339 to the second) and/or an additional
  Cloud Logging filter expression.
- Write logs as JSON Lines:
    * Single file (default),
    * Split per day, or
    * Split per bucket.
- Optionally check access to bucket log views (including private views) before
  collecting, to verify the caller has sufficient permissions.

Authentication uses an installed-app OAuth client (Desktop application) so this script
can be shared publicly. Each user supplies their own OAuth client file.
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import List, Optional, Dict

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# ===== OAuth / API configuration =====

# Read-only scope across Cloud APIs (includes Cloud Logging & Resource Manager).
SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]

# Defaults can be overridden via environment variables.
DEFAULT_CREDENTIALS_FILE = os.environ.get("GCP_OAUTH_CLIENT_SECRETS", "client_secret.json")
DEFAULT_TOKEN_FILE = os.environ.get("GCP_OAUTH_TOKEN_FILE", "token.json")

LOG = logging.getLogger("gcp_log_collector")


# ===== Authentication helpers =====

def get_credentials(credentials_file: str, token_file: str) -> Credentials:
    """
    Obtain user credentials via OAuth2 installed-app flow.

    - If token_file exists and is valid, it is reused.
    - If expired but refresh_token is available, it is refreshed.
    - Otherwise, the browser-based OAuth consent flow is started.

    The resulting token is written back to token_file for reuse.
    """
    creds: Optional[Credentials] = None

    if os.path.exists(token_file):
        LOG.debug("Loading existing token from %s", token_file)
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            LOG.info("Refreshing expired OAuth token...")
            creds.refresh(Request())
        else:
            if not os.path.exists(credentials_file):
                raise FileNotFoundError(
                    f"OAuth client secrets file not found: {credentials_file}. "
                    "See README for setup instructions."
                )

            LOG.info("Starting OAuth browser flow using %s", credentials_file)
            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
            creds = flow.run_local_server(port=0)

        with open(token_file, "w", encoding="utf-8") as token_out:
            token_out.write(creds.to_json())
        LOG.info("Saved refreshed OAuth token to %s", token_file)

    return creds


def get_logging_service(creds: Credentials):
    """Build a Cloud Logging v2 service client."""
    return build("logging", "v2", credentials=creds, cache_discovery=False)


def get_resourcemanager_service(creds: Credentials):
    """Build a Cloud Resource Manager v3 service client."""
    return build("cloudresourcemanager", "v3", credentials=creds, cache_discovery=False)


# ===== Project & bucket helpers =====

def list_projects(creds: Credentials) -> None:
    """
    List projects the caller can see via Cloud Resource Manager v3 projects.search.

    This does *not* read any logs; it only uses metadata from Resource Manager.
    """
    service = get_resourcemanager_service(creds)

    page_token: Optional[str] = None
    header_printed = False

    while True:
        params: Dict[str, str] = {}
        if page_token:
            params["pageToken"] = page_token

        request = service.projects().search(**params)
        response = request.execute()

        projects = response.get("projects", [])
        if not header_printed:
            print("PROJECT_ID\tPROJECT_NAME\tDISPLAY_NAME\tSTATE")
            header_printed = True

        for p in projects:
            full_name = p.get("name", "")
            numeric_id = full_name.split("/")[-1] if full_name else ""
            project_id = p.get("projectId", numeric_id)
            display_name = p.get("displayName", "")
            state = p.get("state", "")
            print(f"{project_id}\t{full_name}\t{display_name}\t{state}")

        page_token = response.get("nextPageToken")
        if not page_token:
            break


def list_log_buckets(logging_service, project_id: str) -> List[dict]:
    """
    List all log buckets in a project (across all locations).

    Returns the raw bucket dicts from the API.
    """
    parent = f"projects/{project_id}/locations/-"
    page_token: Optional[str] = None
    buckets: List[dict] = []

    while True:
        params = {"parent": parent, "pageSize": 100}
        if page_token:
            params["pageToken"] = page_token

        request = logging_service.projects().locations().buckets().list(**params)
        response = request.execute()

        for b in response.get("buckets", []):
            buckets.append(b)

        page_token = response.get("nextPageToken")
        if not page_token:
            break

    return buckets


def list_views_for_bucket(logging_service, bucket_full_name: str) -> List[dict]:
    """
    List all views for a given bucket.

    bucket_full_name example:
        "projects/PROJECT_ID/locations/LOCATION_ID/buckets/BUCKET_ID"
    """
    page_token: Optional[str] = None
    views: List[dict] = []

    while True:
        params = {"parent": bucket_full_name, "pageSize": 100}
        if page_token:
            params["pageToken"] = page_token

        request = logging_service.projects().locations().buckets().views().list(**params)
        response = request.execute()

        for v in response.get("views", []):
            views.append(v)

        page_token = response.get("nextPageToken")
        if not page_token:
            break

    return views


def list_log_buckets_cmd(logging_service, project_id: str, show_views: bool = False) -> None:
    """
    CLI helper: print buckets (and optionally their views) in a project.
    """
    buckets = list_log_buckets(logging_service, project_id)
    if not buckets:
        LOG.warning("No log buckets found in project %s", project_id)
        return

    print("BUCKET_ID\tLOCATION\tFULL_NAME\tRETENTION_DAYS\tLIFECYCLE_STATE")
    for b in buckets:
        full_name = b.get("name", "")
        parts = full_name.split("/")
        bucket_id = parts[-1] if parts else ""
        location = parts[3] if len(parts) >= 4 else "-"
        retention_days = b.get("retentionDays", "")
        lifecycle = b.get("lifecycleState", "")
        print(f"{bucket_id}\t{location}\t{full_name}\t{retention_days}\t{lifecycle}")

        if show_views:
            views = list_views_for_bucket(logging_service, full_name)
            if not views:
                print(f"  VIEW\t<none>\t<no views defined>")
                continue
            for v in views:
                v_name = v.get("name", "")
                v_short = v_name.split("/")[-1] if v_name else ""
                v_desc = v.get("description", "")
                print(f"  VIEW\t{v_short}\t{v_name}\t{v_desc}")


def find_log_bucket(logging_service, project_id: str, bucket_name: str) -> Optional[str]:
    """
    Resolve a log bucket's full resource name by its short name.

    Returns:
        Full bucket name like:
        "projects/PROJECT_ID/locations/LOCATION_ID/buckets/BUCKET_ID"
        or None if not found.
    """
    for bucket in list_log_buckets(logging_service, project_id):
        full_name = bucket.get("name", "")
        short_id = full_name.split("/")[-1] if full_name else ""
        if short_id == bucket_name:
            LOG.info("Matched bucket %s -> %s", bucket_name, full_name)
            return full_name

    LOG.error("Could not find bucket %r in project %r", bucket_name, project_id)
    return None


# ===== Log retrieval and filtering =====

def build_time_filter(start_time: Optional[str], end_time: Optional[str]) -> Optional[str]:
    """
    Build a Cloud Logging filter fragment for a time range.

    Expects start_time / end_time in RFC3339 / ISO8601 format (e.g. 2025-11-29T00:00:00Z).

    Returns:
        Filter string like: 'timestamp >= "..." AND timestamp <= "..."'
        or None if no times are supplied.
    """
    conditions: List[str] = []

    if start_time:
        conditions.append(f'timestamp >= "{start_time}"')
    if end_time:
        conditions.append(f'timestamp <= "{end_time}"')

    if not conditions:
        return None

    return " AND ".join(conditions)


def build_combined_filter(
    start_time: Optional[str],
    end_time: Optional[str],
    extra_filter: Optional[str],
) -> Optional[str]:
    """
    Combine the time filter with an extra Cloud Logging filter expression.

    The extra_filter should be a valid Logging filter expression,
    e.g. 'severity >= ERROR AND logName:"cloudaudit"'.
    """
    time_filter = build_time_filter(start_time, end_time)

    if time_filter and extra_filter:
        return f"({time_filter}) AND ({extra_filter})"
    if time_filter:
        return time_filter
    if extra_filter:
        return extra_filter
    return None


def stream_log_entries(
    logging_service,
    project_id: str,
    bucket_name: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    extra_filter: Optional[str] = None,
    page_size: int = 1000,
):
    """
    Generator that yields log entries as dicts.

    - If bucket_name is None:
        resourceNames = ["projects/PROJECT_ID"] (all buckets in the project).
    - If bucket_name is set:
        resolve it to a bucket, then query the default view "_AllLogs" for that bucket:
        resourceNames = ["projects/.../locations/.../buckets/BUCKET_ID/views/_AllLogs"]

    Time filtering is done via the Logging query language on the timestamp field.
    extra_filter is AND-ed with the time filter, if present.
    """
    if bucket_name:
        bucket_full_name = find_log_bucket(logging_service, project_id, bucket_name)
        if not bucket_full_name:
            raise ValueError(f"Bucket {bucket_name!r} not found in project {project_id!r}")
        resource_names = [f"{bucket_full_name}/views/_AllLogs"]
    else:
        resource_names = [f"projects/{project_id}"]

    filter_str = build_combined_filter(start_time, end_time, extra_filter)

    body: dict = {
        "resourceNames": resource_names,
        "pageSize": page_size,
        "orderBy": "timestamp asc",
    }
    if filter_str:
        body["filter"] = filter_str

    LOG.info(
        "Querying logs for resourceNames=%s filter=%s page_size=%d",
        resource_names,
        filter_str or "<none>",
        page_size,
    )

    page_token: Optional[str] = None

    while True:
        if page_token:
            body["pageToken"] = page_token
        elif "pageToken" in body:
            del body["pageToken"]

        request = logging_service.entries().list(body=body)
        response = request.execute()

        entries = response.get("entries", [])
        for entry in entries:
            yield entry

        page_token = response.get("nextPageToken")
        if not page_token:
            break


def get_entry_date_str(entry: dict) -> str:
    """
    Extract a YYYY-MM-DD date string from a log entry's timestamp.

    Falls back to "no-timestamp" or "invalid-timestamp" if necessary.
    """
    ts = entry.get("timestamp")
    if not ts:
        return "no-timestamp"

    try:
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        return dt.date().isoformat()
    except Exception:
        return "invalid-timestamp"


def collect_logs_to_stream(
    logging_service,
    project_id: str,
    bucket_name: Optional[str],
    start_time: Optional[str],
    end_time: Optional[str],
    output_file: Optional[str],
    output_dir: Optional[str],
    split_mode: str,
    extra_filter: Optional[str],
) -> None:
    """
    Collect logs and write them as JSON Lines, according to split_mode:

    - split_mode == "none" (default):
        Write all entries to a single file (output_file) or stdout if not set.
    - split_mode == "per-day":
        Write entries into one file per date (YYYY-MM-DD.jsonl) in output_dir.
    - split_mode == "per-bucket":
        Write entries into one file per bucket (BUCKET_ID.jsonl) in output_dir.
    """
    if split_mode not in {"none", "per-day", "per-bucket"}:
        raise ValueError(f"Unsupported split_mode: {split_mode}")

    # Default directories if none supplied for split modes
    if split_mode == "per-day" and not output_dir:
        output_dir = "logs_per_day"
    if split_mode == "per-bucket" and not output_dir:
        output_dir = "logs_per_bucket"

    if split_mode == "none":
        # Single stream to either a file or stdout
        if output_file:
            LOG.info("Writing log entries to %s", output_file)
            out_handle = open(output_file, "w", encoding="utf-8")
            close_handle = True
        else:
            LOG.info("Writing log entries to stdout")
            out_handle = sys.stdout
            close_handle = False

        count = 0
        try:
            for entry in stream_log_entries(
                logging_service=logging_service,
                project_id=project_id,
                bucket_name=bucket_name,
                start_time=start_time,
                end_time=end_time,
                extra_filter=extra_filter,
            ):
                out_handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
                count += 1
        finally:
            if close_handle:
                out_handle.close()

        LOG.info("Completed. Wrote %d log entries.", count)
        return

    # Split modes write to multiple files
    if not output_dir:
        raise ValueError("output_dir must be provided for split-mode != 'none'")

    os.makedirs(output_dir, exist_ok=True)

    if split_mode == "per-day":
        LOG.info("Splitting log entries per day into directory %s", output_dir)
        handles: Dict[str, object] = {}
        count = 0
        try:
            for entry in stream_log_entries(
                logging_service=logging_service,
                project_id=project_id,
                bucket_name=bucket_name,
                start_time=start_time,
                end_time=end_time,
                extra_filter=extra_filter,
            ):
                date_str = get_entry_date_str(entry)
                path = os.path.join(output_dir, f"{date_str}.jsonl")
                if date_str not in handles:
                    handles[date_str] = open(path, "a", encoding="utf-8")
                handles[date_str].write(json.dumps(entry, ensure_ascii=False) + "\n")
                count += 1
        finally:
            for h in handles.values():
                try:
                    h.close()
                except Exception:
                    pass

        LOG.info("Completed. Wrote %d log entries into %d day file(s).", count, len(handles))
        return

    if split_mode == "per-bucket":
        LOG.info("Splitting log entries per bucket into directory %s", output_dir)
        count_total = 0

        # Determine which buckets to use
        if bucket_name:
            bucket_ids = [bucket_name]
        else:
            buckets = list_log_buckets(logging_service, project_id)
            if not buckets:
                LOG.warning("No log buckets found in project %s", project_id)
                return
            bucket_ids = []
            for b in buckets:
                full_name = b.get("name", "")
                if not full_name:
                    continue
                bucket_ids.append(full_name.split("/")[-1])

        for b_id in bucket_ids:
            out_path = os.path.join(output_dir, f"{b_id}.jsonl")
            LOG.info("Collecting logs for bucket %s into %s", b_id, out_path)
            with open(out_path, "w", encoding="utf-8") as fh:
                for entry in stream_log_entries(
                    logging_service=logging_service,
                    project_id=project_id,
                    bucket_name=b_id,
                    start_time=start_time,
                    end_time=end_time,
                    extra_filter=extra_filter,
                ):
                    fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
                    count_total += 1

        LOG.info(
            "Completed. Wrote %d log entries across %d bucket file(s).",
            count_total,
            len(bucket_ids),
        )


# ===== Private log view access check =====

def check_private_views(logging_service, project_id: str, bucket_name: Optional[str]) -> None:
    """
    Check access to log views for the relevant bucket(s) and print a simple status table.

    This is best-effort: it attempts a minimal entries.list call against each view
    (including _AllLogs). If a 403/404 is returned, it marks that view as not accessible.
    """
    if bucket_name:
        bucket_full = find_log_bucket(logging_service, project_id, bucket_name)
        if not bucket_full:
            LOG.error("Cannot check views: bucket %r not found in project %r", bucket_name, project_id)
            return
        bucket_full_names = [bucket_full]
    else:
        bucket_full_names = [b.get("name", "") for b in list_log_buckets(logging_service, project_id)]
        bucket_full_names = [b for b in bucket_full_names if b]

    if not bucket_full_names:
        LOG.warning("No buckets found to check views in project %s", project_id)
        return

    print("BUCKET_ID\tVIEW_ID\tSTATUS\tNOTE")

    for bucket_full in bucket_full_names:
        bucket_id = bucket_full.split("/")[-1]
        views = list_views_for_bucket(logging_service, bucket_full)
        if not views:
            print(f"{bucket_id}\t<no-views>\tN/A\tno views defined")
            continue

        for v in views:
            v_name = v.get("name", "")
            view_id = v_name.split("/")[-1] if v_name else ""
            status = "UNKNOWN"
            note = ""

            try:
                body = {
                    "resourceNames": [v_name],
                    "pageSize": 1,
                    "orderBy": "timestamp desc",
                }
                req = logging_service.entries().list(body=body)
                _ = req.execute()
                status = "OK"
                note = "view readable"
            except HttpError as http_err:
                code = getattr(http_err.resp, "status", None)
                if code in (403, 404):
                    status = "NO_ACCESS"
                    note = f"HTTP {code}: {http_err}"
                else:
                    status = "ERROR"
                    note = f"HTTP {code}: {http_err}"

            print(f"{bucket_id}\t{view_id}\t{status}\t{note}")


# ===== CLI / argument parsing =====

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect logs from Google Cloud Logging using OAuth2 user credentials.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--credentials-file",
        default=DEFAULT_CREDENTIALS_FILE,
        help=(
            "Path to OAuth client secrets JSON file (Desktop application). "
            "Each user supplies their own file; do NOT commit this to version control."
        ),
    )
    parser.add_argument(
        "--token-file",
        default=DEFAULT_TOKEN_FILE,
        help=(
            "Path to the OAuth token cache file (per-user). "
            "Safe to delete if you want to force re-authentication."
        ),
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("LOG_LEVEL", "INFO"),
        help="Logging level (DEBUG, INFO, WARNING, ERROR).",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # list-projects
    subparsers.add_parser(
        "list-projects",
        help="List projects the current user can access (via Cloud Resource Manager).",
    )

    # list-buckets
    list_buckets_p = subparsers.add_parser(
        "list-buckets",
        help="List log buckets in a project (and optionally their views).",
    )
    list_buckets_p.add_argument(
        "--project-id",
        required=True,
        help="Google Cloud project ID (e.g. my-ir-project).",
    )
    list_buckets_p.add_argument(
        "--show-views",
        action="store_true",
        help="Also list views defined in each bucket.",
    )

    # collect-logs
    collect = subparsers.add_parser(
        "collect-logs",
        help=(
            "Collect log entries from Cloud Logging.\n"
            "- Without --bucket: all buckets in the project.\n"
            "- With --bucket: only that specific bucket."
        ),
    )
    collect.add_argument(
        "--project-id",
        required=True,
        help="Google Cloud project ID (e.g. my-ir-project).",
    )
    collect.add_argument(
        "--bucket",
        help=(
            "Optional log bucket short name in the project. "
            "If omitted, retrieves logs from all buckets in the project."
        ),
    )
    collect.add_argument(
        "--start-time",
        help=(
            "Optional start time (inclusive) as RFC3339 / ISO8601, "
            'e.g. "2025-11-29T00:00:00Z".'
        ),
    )
    collect.add_argument(
        "--end-time",
        help=(
            "Optional end time (inclusive) as RFC3339 / ISO8601, "
            'e.g. "2025-11-30T23:59:59Z".'
        ),
    )
    collect.add_argument(
        "--filter",
        help=(
            "Additional Cloud Logging filter expression to AND with the time range. "
            "Example: 'severity >= ERROR AND logName:\"cloudaudit\"'."
        ),
    )
    collect.add_argument(
        "-o",
        "--output",
        help=(
            "Output file for JSON Lines when split-mode is 'none'. "
            "If omitted, entries are printed to stdout."
        ),
    )
    collect.add_argument(
        "--split-mode",
        choices=["none", "per-day", "per-bucket"],
        default="none",
        help=(
            "How to split output files. "
            "'none' (default) writes everything to a single file/stdout; "
            "'per-day' writes one file per date; "
            "'per-bucket' writes one file per log bucket."
        ),
    )
    collect.add_argument(
        "--output-dir",
        help=(
            "Directory for output files when using split-mode 'per-day' or 'per-bucket'. "
            "Defaults to 'logs_per_day' or 'logs_per_bucket' if not set."
        ),
    )
    collect.add_argument(
        "--check-private-views",
        action="store_true",
        help=(
            "Before collecting, check access to log views (including private log views) "
            "in the relevant bucket(s) and print a status table."
        ),
    )

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    try:
        creds = get_credentials(args.credentials_file, args.token_file)
    except Exception as exc:
        LOG.error("Authentication failed: %s", exc)
        return 1

    try:
        if args.command == "list-projects":
            list_projects(creds)
            return 0

        logging_service = get_logging_service(creds)

        if args.command == "list-buckets":
            list_log_buckets_cmd(logging_service, args.project_id, args.show_views)
            return 0

        if args.command == "collect-logs":
            if args.check_private_views:
                LOG.info("Checking access to log views (including private views)...")
                check_private_views(logging_service, args.project_id, args.bucket)

            collect_logs_to_stream(
                logging_service=logging_service,
                project_id=args.project_id,
                bucket_name=args.bucket,
                start_time=args.start_time,
                end_time=args.end_time,
                output_file=args.output,
                output_dir=args.output_dir,
                split_mode=args.split_mode,
                extra_filter=args.filter,
            )
            return 0

        LOG.error("Unknown command: %s", args.command)
        return 2

    except HttpError as http_err:
        LOG.error("API call failed: %s", http_err)
        return 1
    except KeyboardInterrupt:
        LOG.warning("Interrupted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
