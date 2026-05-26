#!/usr/bin/env python3
import shutil
import sys
import time

from github_watcher_lib import (
    all_watches,
    bool_value,
    event_payload,
    fail,
    github_request,
    list_value,
    load_config,
    parse_time,
    plugin_state_dir,
    prompt_agent,
    publish_event,
    read_json,
    render_template,
    seen_path,
    should_accept_author,
    static_watches,
    string_value,
    update_watermark,
    utc_now,
    write_json,
)


def fetch_comments(watch):
    comments = []
    page = 1
    while True:
        items = github_request(
            f"/repos/{watch['repo']}/issues/{watch['number']}/comments",
            watch["provider"],
            {"per_page": 100, "page": page, "sort": "updated", "direction": "asc"},
        )
        comments.extend(items)
        if len(items) < 100:
            return comments
        page += 1


def fetch_reviews(watch):
    reviews = []
    page = 1
    while True:
        items = github_request(
            f"/repos/{watch['repo']}/pulls/{watch['number']}/reviews",
            watch["provider"],
            {"per_page": 100, "page": page},
        )
        reviews.extend(items)
        if len(items) < 100:
            return reviews
        page += 1


def fetch_pull(watch):
    return github_request(f"/repos/{watch['repo']}/pulls/{watch['number']}", watch["provider"])


def fetch_check_runs(watch, sha):
    return github_request(
        f"/repos/{watch['repo']}/commits/{sha}/check-runs",
        watch["provider"],
        {"per_page": 100},
    ).get("check_runs", [])


def check_status(check_runs):
    if not check_runs:
        return "none", "No check runs were found."
    if any(run.get("status") != "completed" for run in check_runs):
        return "pending", "Some check runs are still pending."
    conclusions = {run.get("conclusion") for run in check_runs}
    if conclusions & {"failure", "timed_out", "cancelled", "action_required"}:
        failed = [run.get("name", "<unnamed>") for run in check_runs if run.get("conclusion") in {"failure", "timed_out", "cancelled", "action_required"}]
        return "failed", "Failed checks: " + ", ".join(failed)
    if conclusions <= {"success", "skipped", "neutral"}:
        return "passed", "All check runs passed."
    return "pending", "Check runs are not complete."


def publish_and_prompt(watch, event_name, payload, prompt_config, prompt_enabled):
    if watch["publish"]["enabled"] or prompt_enabled:
        publish_event(event_name, payload)
    if prompt_enabled:
        values = {key: value for key, value in payload.items() if isinstance(value, (str, int))}
        values["labels"] = ", ".join(watch.get("labels", [])) or "-"
        prompt_agent(render_template(prompt_config.get("template"), values))


def process_comments(watch, seen):
    config = watch["comments"]
    if not config["enabled"]:
        return
    key = f"{watch['repo']}#{watch['number']}:comments"
    watermark = seen.get(key)
    max_seen = watermark or 0
    seen.setdefault(key, max_seen)

    for comment in fetch_comments(watch):
        timestamp = parse_time(comment.get("updated_at") or comment.get("created_at"))
        if timestamp <= max_seen:
            continue
        if not should_accept_author(comment, config["author-associations"]):
            update_watermark(seen, key, timestamp)
            continue
        payload = event_payload(
            watch,
            f"comment:{comment.get('id')}",
            "comment",
            author=(comment.get("user") or {}).get("login", ""),
            author_association=comment.get("author_association", ""),
            body=comment.get("body") or "",
            summary=(comment.get("body") or "")[:500],
            html_url=comment.get("html_url", ""),
            created_at=comment.get("created_at", ""),
            updated_at=comment.get("updated_at", ""),
        )
        if watermark is not None:
            publish_and_prompt(watch, "plugin.github.pr.comment", payload, config["prompt"], config["prompt"]["enabled"])
        update_watermark(seen, key, timestamp)


def process_reviews(watch, seen):
    config = watch["reviews"]
    if not config["enabled"]:
        return
    key = f"{watch['repo']}#{watch['number']}:reviews"
    watermark = seen.get(key)
    max_seen = watermark or 0
    seen.setdefault(key, max_seen)

    for review in fetch_reviews(watch):
        timestamp = parse_time(review.get("submitted_at") or review.get("updated_at"))
        if timestamp <= max_seen:
            continue
        if not should_accept_author(review, config["author-associations"]):
            update_watermark(seen, key, timestamp)
            continue
        payload = event_payload(
            watch,
            f"review:{review.get('id')}",
            "review",
            author=(review.get("user") or {}).get("login", ""),
            author_association=review.get("author_association", ""),
            state=review.get("state", ""),
            body=review.get("body") or "",
            summary=(review.get("body") or review.get("state") or "")[:500],
            html_url=review.get("html_url", ""),
            submitted_at=review.get("submitted_at", ""),
        )
        if watermark is not None:
            publish_and_prompt(watch, "plugin.github.pr.review", payload, config["prompt"], config["prompt"]["enabled"])
        update_watermark(seen, key, timestamp)


def process_checks(watch, seen):
    config = watch["checks"]
    if not config["enabled"]:
        return
    pull = fetch_pull(watch)
    sha = ((pull.get("head") or {}).get("sha") or "").strip()
    if not sha:
        return
    status, summary = check_status(fetch_check_runs(watch, sha))
    key = f"{watch['repo']}#{watch['number']}:checks"
    previous = seen.get(key)
    seen[key] = status
    if previous is None or previous == status:
        return
    should_publish = (
        (status == "failed" and config["publish-failed-transition"])
        or (status == "passed" and config["publish-passed-transition"])
    )
    prompt_enabled = (
        (status == "failed" and config["prompt"]["failed"])
        or (status == "passed" and config["prompt"]["passed"])
    )
    if not should_publish and not prompt_enabled:
        return
    payload = event_payload(
        watch,
        f"checks:{sha}:{status}",
        "checks",
        sha=sha,
        status=status,
        previous_status=previous,
        summary=summary,
    )
    publish_and_prompt(watch, "plugin.github.pr.checks", payload, config["prompt"], prompt_enabled)


def process_watch(watch, seen):
    process_comments(watch, seen)
    process_reviews(watch, seen)
    process_checks(watch, seen)


def run_once(config):
    seen = read_json(seen_path(), {})
    for watch in all_watches(config):
        try:
            process_watch(watch, seen)
        except SystemExit:
            raise
        except Exception as error:
            print(f"github-watcher: {watch['repo']}#{watch['number']} failed: {error}", file=sys.stderr, flush=True)
    write_json(seen_path(), seen)


def run_loop():
    config = load_config()
    poll_seconds = config.get("poll-seconds", 60)
    if not isinstance(poll_seconds, int) or poll_seconds < 5:
        fail("poll-seconds must be an integer >= 5")
    print(f"github-watcher: watching {len(all_watches(config))} PR(s)", flush=True)
    while True:
        config = load_config()
        run_once(config)
        time.sleep(poll_seconds)


def doctor():
    if shutil.which("git-host-credential") is None:
        fail("git-host-credential not found on PATH")
    if shutil.which("agentdctl") is None:
        fail("agentdctl not found on PATH")
    config = load_config()
    static = static_watches(config)
    for watch in static:
        if not string_value(watch.get("provider"), "provider"):
            fail(f"{watch['repo']}#{watch['number']} has no provider")
    print(f"github-watcher: {len(static)} static PR watch(es) look valid")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "doctor":
        doctor()
        return
    if len(sys.argv) > 1 and sys.argv[1] == "once":
        run_once(load_config())
        return
    plugin_state_dir().mkdir(parents=True, exist_ok=True)
    run_loop()


if __name__ == "__main__":
    main()
