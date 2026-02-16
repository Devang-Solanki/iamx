import os
import re
import json
import uuid
import shutil
import tempfile
import subprocess
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from publicsuffix2 import get_sld
import boto3
import sqs_extended_client

#Configure SQS Extended Client properties
sqs_extended_client = boto3.client("sqs", region_name="eu-west-2")
sqs_extended_client.large_payload_support = "github-secrets-sqs-extender" 
sqs_extended_client.use_legacy_attribute = False

# Normal SQS client
normal_sqs = boto3.client("sqs", region_name="eu-west-2")

# -----------------------------------------------------------------------------
# Logging setup
# -----------------------------------------------------------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)  # ensure INFO logs are emitted in Lambda

for h in logger.handlers:
    h.setLevel(logging.INFO)   # optional but makes it explicit

# env config
SQS_QUEUE_URL_PROD_ELASTIC = "https://sqs.eu-west-2.amazonaws.com/021891571420/prod-elasticNode2"
SQS_QUEUE_URL_SECRETS_SCANNER = "https://sqs.eu-west-2.amazonaws.com/021891571420/github-patch-file"
SQS_QUEUE_URL_SECRETS_SCANNER_LARGE = "https://sqs.eu-west-2.amazonaws.com/021891571420/github-patch-file-large"
FETCH_THRESHOLD_MB = float(os.environ.get("FETCH_THRESHOLD_MB", "100"))  # currently unused (kept for compatibility)
FETCH_DEPTH = int(os.environ.get("FETCH_DEPTH", "50"))
EMAIL_DOMAIN_RE = re.compile(r"@([^@]+)$")
AUTHOR_LINE_RE = re.compile(r'^(?:author|committer)\s+(.+)\s+<([^>]+)>\s+(\d+)\s+([+-]\d{4})$')

# boto3 client (Lambda's role should have sqs:SendMessage)
sqs = boto3.client("sqs")

MAX_SQS_BYTES = 1000 * 1024  # 1000 KB (or use 1024*1024 for full 1 MiB)

def iso_now():
    return datetime.now(timezone.utc).isoformat()


def extract_domain(email: str):
    if not email or not isinstance(email, str):
        return None
    m = EMAIL_DOMAIN_RE.search(email)
    if not m:
        return None
    return m.group(1)


def run_git_command(cmd, cwd=None, description=None, capture_stdout=True):
    """
    Run a git command using subprocess.run and return stdout (if captured).
    Raises RuntimeError on non-zero exit code with detailed logging.
    """
    desc = description or " ".join(cmd)
    # logger.info("Running command: %s (cwd=%s)", desc, cwd)

    result = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE if capture_stdout else None,
        stderr=subprocess.PIPE,
    )

    if result.returncode != 0:
        logger.error(
            "Command failed: %s | returncode=%s | stdout=%s | stderr=%s",
            desc,
            result.returncode,
            result.stdout,
            result.stderr,
        )
        raise RuntimeError(
            f"Command failed: {desc}; returncode={result.returncode}; stderr={result.stderr}"
        )

    return result.stdout if capture_stdout else ""


def parse_commit_object(commit_sha: str, cat_file_output: str, is_org, login, hour, repo):
    """
    Parse commit text from `git cat-file -p <sha>` into the expected fields.
    Returns dict similar to previous JS shape.
    """
    lines = cat_file_output.splitlines()
    if not lines:
        # logger.warning("Empty cat-file output for commit %s", commit_sha)
        message = ""
    else:
        # previous behavior: use last line, truncated to 100 chars
        message = lines[-1].strip()[:100]

    author_line = next((h for h in lines if h.startswith("author ")), "")
    # author format: author Name <email> <unix-ts> +TZ
    m = AUTHOR_LINE_RE.match(author_line)
    author_name = None
    author_email = None
    author_date = None
    if m:
        author_name = m.group(1).strip()
        author_email = m.group(2).strip()
        ts = int(m.group(3)) * 1000
        author_date = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).isoformat()
    # else:
    #     logger.warning("Could not parse author line for commit %s: %s", commit_sha, author_line)

    author_domain = extract_domain(author_email) or ""
    try:
        author_domain = get_sld(author_domain)
    except Exception:
        # Don't break on publicsuffix parsing issues; keep raw domain
        logger.exception("Failed to resolve SLD for domain '%s'", author_domain)

    return {
        "commit_id": commit_sha,
        "author_name": author_name,
        "author_email": author_email,
        "message": message,
        "@timestamp": author_date,
        "domain": author_domain,
        "is_org": is_org,
        "gh_username": login,
        "gh_key": hour,
        "repo": repo,
    }


def process_payload(payload_obj: dict, fetch_threshold_mb: float = FETCH_THRESHOLD_MB):
    """
    Process a single payload: clones metadata, fetches head (monitored), lists commits and parses them.
    Supports PushEvent (existing behavior) and CreateEvent for branch creation.
    Returns a dict with commits list and fetch metrics (start/end/duration/packSize/reportedSize).
    May raise on errors (so caller can record them).
    """

    # logger.info("Processing payload: %s", json.dumps(payload_obj))

    repo_name = payload_obj.get("repo", {}).get("name")
    is_org = payload_obj.get("is_org")
    login = payload_obj.get("actor", {}).get("login")
    hour = payload_obj.get("hour")
    event_type = payload_obj.get("event_type")

    if not repo_name:
        raise ValueError("Missing repo.name in message body")

    # create temp dir
    tmp_base = tempfile.mkdtemp(prefix="gitfetch-")
    repo_id = str(uuid.uuid4())
    repo_dir = os.path.join(tmp_base, repo_id)
    os.makedirs(repo_dir, exist_ok=True)

    # logger.info("Created temporary repo directory: %s", repo_dir)

    try:
        # init repo and add remote
        run_git_command(["git", "init"], cwd=repo_dir, description="git init")
        run_git_command(
            ["git", "remote", "add", "origin", f"https://github.com/{repo_name}.git"],
            cwd=repo_dir,
            description="git remote add origin",
            capture_stdout=False,
        )

        # --- Existing PushEvent behavior ---
        if event_type == "PushEvent":
            payload = payload_obj.get("payload", {})
            before = payload.get("before")
            head = payload.get("head")
            if not before or not head:
                raise ValueError("Missing payload.before or payload.head for PushEvent")

            # fetch head
            # logger.info("Processing PushEvent for repo %s: before=%s head=%s", repo_name, before, head)
            try:
                result = subprocess.run(
                    [
                        "git",
                        "-c", "pack.window=0",
                        "-c", "pack.depth=1",
                        "-c", "core.deltaBaseCacheLimit=64m",
                        "fetch",
                        "--depth", str(FETCH_DEPTH),
                        "--no-tags",
                        "--filter=blob:none",
                        "origin",
                        head,
                    ],
                    cwd=repo_dir,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if result.returncode != 0:
                    logger.error(
                        "git fetch failed (PushEvent): returncode=%s, stdout=%s, stderr=%s",
                        result.returncode,
                        result.stdout,
                        result.stderr,
                    )
                    raise RuntimeError(
                        f"git fetch failed with exit code {result.returncode}:\n{result.stderr or result.stdout}"
                    )
            except Exception:
                logger.exception("Failed to fetch head for PushEvent")
                raise

            # list commits between before..head (or reversed if empty)
            try:
                revlist_out = run_git_command(
                    ["git", "rev-list", f"{before}..{head}"],
                    cwd=repo_dir,
                    description=f"git rev-list {before}..{head}",
                )
            except RuntimeError:
                logger.warning("git rev-list %s..%s failed or returned no output, will try reverse range", before, head)
                revlist_out = ""

            if not revlist_out.strip():
                revlist_out = run_git_command(
                    ["git", "rev-list", f"{head}..{before}"],
                    cwd=repo_dir,
                    description=f"git rev-list {head}..{before}",
                )

            commit_shas = [ln.strip() for ln in revlist_out.splitlines() if ln.strip()]

        # --- New CreateEvent handling ---
        elif event_type == "CreateEvent":
            payload = payload_obj.get("payload", {})
            ref_type = payload.get("ref_type")
            full_ref = payload.get("full_ref")
            ref = payload.get("ref")  # e.g. "feature/xyz"
            master_branch = payload.get("master_branch")  # e.g. "main" (may be None)

            # logger.info(
            #     "Processing CreateEvent for repo %s: ref_type=%s full_ref=%s ref=%s master_branch=%s",
            #     repo_name,
            #     ref_type,
            #     full_ref,
            #     ref,
            #     master_branch,
            # )

            # We only handle branch creations here
            if ref_type != "branch" or not full_ref:
                # logger.info("CreateEvent is not a branch or missing full_ref; no commits to process")
                commit_shas = []
            else:
                # Note: keeping same behavior (fetch master_branch and full_ref)
                fetch_cmd = [
                    "git",
                    "-c", "pack.window=0",
                    "-c", "pack.depth=1",
                    "-c", "core.deltaBaseCacheLimit=64m",
                    "fetch",
                    "--depth",
                    str(FETCH_DEPTH),
                    "--no-tags",
                    "--filter=blob:none",
                    "origin",
                    master_branch,
                    full_ref,
                ]
                result = subprocess.run(
                    fetch_cmd,
                    cwd=repo_dir,
                    text=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )

                if result.returncode != 0:
                    stderr_lower = (result.stderr or "").lower()
                    logger.error(
                        "git fetch failed (CreateEvent): returncode=%s, stderr=%s",
                        result.returncode,
                        result.stderr,
                    )
                    # detect common variations of the remote-ref-not-found message
                    if (
                        "couldn't find remote ref" in stderr_lower
                        or "could not find remote ref" in stderr_lower
                        or "remote ref not found" in stderr_lower
                    ):
                        logger.info("Remote branch not found for CreateEvent; returning no_branch")
                        return {
                            "commits": [],
                            "hour": hour,
                            "reason": "no_branch",
                        }
                    # For other failures, raise with stderr for visibility
                    raise RuntimeError(
                        f"git fetch for full_ref failed (exit {result.returncode}): {result.stderr.strip()}"
                    )

                # Resolve fetched head (origin/<branch>)
                try:
                    before_sha = run_git_command(
                        ["git", "rev-parse", f"origin/{master_branch}"],
                        cwd=repo_dir,
                        description=f"git rev-parse origin/{master_branch}",
                    ).strip()
                    head_sha = run_git_command(
                        ["git", "rev-parse", f"origin/{ref}"],
                        cwd=repo_dir,
                        description=f"git rev-parse origin/{ref}",
                    ).strip()
                except RuntimeError:
                    logger.exception("Failed to resolve before/head SHAs for CreateEvent")
                    raise

                # logger.info("CreateEvent SHAs: before_sha=%s head_sha=%s", before_sha, head_sha)

                if before_sha != head_sha:
                    try:
                        revlist_out = run_git_command(
                            ["git", "rev-list", f"{before_sha}..{head_sha}"],
                            cwd=repo_dir,
                            description=f"git rev-list {before_sha}..{head_sha}",
                        )
                    except RuntimeError:
                        logger.warning(
                            "git rev-list %s..%s failed or returned no output, trying reverse",
                            before_sha,
                            head_sha,
                        )
                        revlist_out = ""

                    if not revlist_out.strip():
                        revlist_out = run_git_command(
                            ["git", "rev-list", f"{head_sha}..{before_sha}"],
                            cwd=repo_dir,
                            description=f"git rev-list {head_sha}..{before_sha}",
                        )
                else:
                    revlist_out = run_git_command(
                        ["git", "rev-list", f"{head_sha}"],
                        cwd=repo_dir,
                        description=f"git rev-list {head_sha}",
                    )

                commit_shas = [ln.strip() for ln in revlist_out.splitlines() if ln.strip()]

        else:
            # For other event types we don't produce commits
            # logger.info("Unsupported event_type=%s; no commits to process", event_type)
            commit_shas = []

        logger.info("Found %d commit(s) to process", len(commit_shas))

        commits = []
        # if commit_shas:
        #     logger.info("Fetching missing blobs once for %d commits", len(commit_shas))
        #     run_git_command(
        #         ["git", "fetch", "origin", "--filter=blob:limit=0"],
        #         cwd=repo_dir,
        #         description="git fetch blobs once",
        #         capture_stdout=False,
        #     )
        emails = {}
        SCAN_PATCH_NON_FREE = os.getenv("SCAN_PATCH_NON_FREE")
        if SCAN_PATCH_NON_FREE == "1":
            from free_emails import FREE_EMAILS
            emails = FREE_EMAILS

        for sha in commit_shas:
            cat_out = run_git_command(
                ["git", "cat-file", "-p", sha],
                cwd=repo_dir,
                description=f"git cat-file -p {sha}",
            )
            obj = parse_commit_object(sha, cat_out, is_org, login, hour, repo_name)
            SCAN_PATCH = os.getenv("SCAN_PATCH")
            if SCAN_PATCH == "1":
                if SCAN_PATCH_NON_FREE == "1":
                    if obj['domain'] in emails:
                        commits.append(obj)
                        continue
                patch = run_git_command(["git", "show", "--format=full", obj['commit_id']], cwd=repo_dir, description="get patch files", capture_stdout=True)
                obj["patch"] = patch
            
            commits.append(obj)

        result = {
            "commits": commits,
            "hour": hour,
        }

        return result
    finally:
        # cleanup
        try:
            shutil.rmtree(tmp_base)
            # logger.info("Removed temporary directory %s", tmp_base)
        except Exception:
            logger.exception("Failed to remove temporary directory %s", tmp_base)


def send_to_sqs(obj: dict, SQS_URL: str):
    """Send the JSON object to SQS queue if configured. Returns response dict or None if no queue."""
    if not SQS_URL:
        logger.warning("SQS_URL not configured; skipping send_to_sqs")
        return None
    body = json.dumps(obj)
    size_bytes = len(body.encode("utf-8"))
    if size_bytes >= MAX_SQS_BYTES and SQS_URL == SQS_QUEUE_URL_SECRETS_SCANNER:
        send_to_sqs_extender(body, SQS_QUEUE_URL_SECRETS_SCANNER_LARGE)
        return
    try:
        resp = sqs.send_message(QueueUrl=SQS_URL, MessageBody=body)
        # logger.info("Sent message to SQS: MessageId=%s", resp.get("MessageId"))
        return resp
    except Exception as e:
        # log and return None to caller
        logger.exception("Failed to send to SQS")
        return None

def send_to_sqs_extender(obj: str, SQS_URL: str):
    """Send the JSON object to SQS queue if configured. Returns response dict or None if no queue."""
    if not SQS_URL:
        logger.warning("SQS_URL not configured; skipping send_to_sqs")
        return None
    try:
        send_message_response = sqs_extended_client.send_message(
            QueueUrl=SQS_URL,
            MessageBody=obj
        )
        # logger.info("Sent message to SQS: MessageId=%s", resp.get("MessageId"))
        return send_message_response
    except Exception as e:
        # log and return None to caller
        logger.exception("Failed to send to SQS")
        return None


def lambda_handler(event, context):
    """
    Lambda entrypoint. Expects SQS event style: event['Records'] = list of { 'messageId', 'body' }
    Returns JSON with per-record results or an error.
    """
    # logger.info("Received event: %s", json.dumps(event))

    # x = ls(event, context)
    # return x

    try:
        records = event.get("Records")
        if not isinstance(records, list):
            msg = "Expected SQS event with Records array"
            logger.error(msg)
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": msg}),
            }

        results = []

        for rec in records:
            message_id = rec.get("messageId")
            start_time = iso_now()
            start_ts = time.time()

            body_raw = rec.get("body")
            try:
                body_obj = json.loads(body_raw) if isinstance(body_raw, str) else body_raw
            except json.JSONDecodeError:
                logger.exception("Failed to decode SQS message body as JSON: %s", body_raw)
                raise

            payload_result = process_payload(body_obj, fetch_threshold_mb=FETCH_THRESHOLD_MB)
            end_time = iso_now()
            duration = time.time() - start_ts

            h = payload_result.get("hour")
            if not h:
                raise RuntimeError("Missing 'hour' in payload_result")
            
            splits = h.split("-")
            if len(splits) < 2:
                raise RuntimeError(f"Unexpected 'hour' format: {h}")
            index = splits[0] + "-" + splits[1]

            commits = payload_result.get("commits", [])
            if len(commits) > 0:
                out_obj = {
                    "messageId": message_id,
                    "data": commits,
                    "fetch": payload_result.get("fetch"),  # unchanged; may be None
                    "startTime": start_time,
                    "endTime": end_time,
                    "durationSeconds": duration,
                    "index": "github-commits-v-" + index,
                }
                
                for c in out_obj['data']:
                    if c.get('patch'):
                        send_to_sqs(c, SQS_QUEUE_URL_SECRETS_SCANNER)
                        c.pop('patch', None)

                # send to SQS
                sqs_resp = send_to_sqs(out_obj, SQS_QUEUE_URL_PROD_ELASTIC)
                if sqs_resp is not None:
                    out_obj["sqsMessageId"] = sqs_resp.get("MessageId")

                results.append(out_obj)
            else:
                reason = payload_result.get("reason")
                if reason == "no_branch":
                    # logger.info("No commits due to no_branch reason")
                    return {
                        "statusCode": 200,
                        "headers": {"Content-Type": "application/json"},
                        "body": "no_branch",
                    }
                logger.error("No commits found in payload_result and no 'no_branch' reason")
                raise RuntimeError("No Commits found")
            
        # for obj in results:
        #     for c in obj['data']:
        #         c['patch_files'] = patch
        #         sqs_resp = send_to_sqs(c, SQS_QUEUE_URL_SECRETS_SCANNER)

        # final response
        # logger.info("Results: %s", json.dumps(results))
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(results),
        }

    except Exception as e:
        # Catch-all: log full stack and return a 500 with message
        logger.exception("Error processing Lambda event")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": str(e)}),
        }