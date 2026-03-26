"""CLI entry points for VulnRadar.

Contains all ``argparse`` logic and the ``main_etl()`` / ``main_notify()``
functions.  The top-level ``etl.py`` and ``notify.py`` scripts are thin
shims that call into this module, preserving backward compatibility with
existing GitHub Actions workflows.
"""

import argparse
import datetime as dt
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any, Sequence

from .config import WatchlistConfig, find_watchlist, load_merged_watchlist
from .downloaders import (
    download_and_extract_zip,
    download_bytes,
    download_cisa_kev,
    download_epss,
    download_nvd_feeds,
    download_patchthis,
    get_latest_cvelist_zip_url,
    requests_session,
)
from .enrichment import (
    build_radar_data,
    extract_all_vendors_products,
    load_vendor_split,
    write_radar_data,
    write_vendor_split,
)
from .notifications import load_providers
from .notifications.github_issues import GitHubIssueProvider
from .parsers import fuzzy_score, norm
from .report import write_markdown_report
from .state import Change, StateManager


def _default_min_year() -> int:
    """Inclusive lower bound year for the default scan window."""
    return dt.datetime.now().year - 4


# ─── ETL CLI ──────────────────────────────────────────────────────────────────


def _handle_discovery_commands(args: argparse.Namespace) -> int:
    """Handle --list-vendors, --list-products, --validate-watchlist commands."""
    session = requests_session()

    print("Downloading CVE List V5 bulk export for discovery...")
    zip_url = get_latest_cvelist_zip_url(session)
    zip_bytes = download_bytes(session, zip_url)
    extracted = download_and_extract_zip(zip_bytes)

    try:
        current_year = dt.datetime.now().year
        years = [current_year - 1, current_year]

        print("Scanning CVE data (last 2 years)...")
        all_vendors, all_products = extract_all_vendors_products(extracted, years)
        print(f"  Found {len(all_vendors)} unique vendors, {len(all_products)} unique products")
        print()

        if args.list_vendors is not None:
            filter_str = (args.list_vendors or "").lower()
            matches = sorted(v for v in all_vendors if filter_str in v)
            if filter_str:
                print(f"Vendors containing '{filter_str}' ({len(matches)} matches):")
            else:
                print(f"All vendors ({len(matches)} total):")
            print("-" * 50)
            for v in matches[:200]:
                print(f"  {v}")
            if len(matches) > 200:
                print(f"  ... and {len(matches) - 200} more")
            return 0

        if args.list_products is not None:
            filter_str = (args.list_products or "").lower()
            matches = sorted(p for p in all_products if filter_str in p)
            if filter_str:
                print(f"Products containing '{filter_str}' ({len(matches)} matches):")
            else:
                print(f"All products ({len(matches)} total):")
            print("-" * 50)
            for p in matches[:200]:
                print(f"  {p}")
            if len(matches) > 200:
                print(f"  ... and {len(matches) - 200} more")
            return 0

        if args.validate_watchlist:
            watchlist_path = args.watchlist if args.watchlist else find_watchlist()
            if not Path(watchlist_path).exists():
                print(f"❌ Watchlist not found: {watchlist_path}")
                return 1

            print(f"Validating watchlist: {watchlist_path}")
            print("=" * 60)
            wl = load_merged_watchlist(Path(watchlist_path))

            print(f"\n📋 Vendors ({len(wl.vendors)} in watchlist):")
            matched_vendors = 0
            unmatched_vendors: list[str] = []
            for wv in sorted(wl.vendors):
                matches = [v for v in all_vendors if wv in v or v in wv]
                if matches:
                    matched_vendors += 1
                    print(f"  ✅ {wv} → matches {len(matches)} vendor(s)")
                else:
                    unmatched_vendors.append(wv)
                    print(f"  ⚠️  {wv} → no matches found (may still match future CVEs)")

            print(f"\n📦 Products ({len(wl.products)} in watchlist):")
            matched_products = 0
            unmatched_products: list[str] = []
            for wp in sorted(wl.products):
                matches = [p for p in all_products if wp in p or p in wp]
                if matches:
                    matched_products += 1
                    print(f"  ✅ {wp} → matches {len(matches)} product(s)")
                else:
                    unmatched_products.append(wp)
                    print(f"  ⚠️  {wp} → no matches found (may still match future CVEs)")

            print("\n" + "=" * 60)
            print("Summary:")
            print(f"  Vendors:  {matched_vendors}/{len(wl.vendors)} matched")
            print(f"  Products: {matched_products}/{len(wl.products)} matched")

            if unmatched_vendors or unmatched_products:
                print("\n💡 Suggestions for unmatched terms:")
                for uv in unmatched_vendors[:5]:
                    suggestions = sorted(all_vendors, key=lambda v: fuzzy_score(uv, v), reverse=True)[:3]
                    print(f"  '{uv}' → try: {', '.join(suggestions)}")
                for up in unmatched_products[:5]:
                    suggestions = sorted(all_products, key=lambda p: fuzzy_score(up, p), reverse=True)[:3]
                    print(f"  '{up}' → try: {', '.join(suggestions)}")
            return 0

    finally:
        shutil.rmtree(extracted, ignore_errors=True)

    return 0


def _years_to_process(min_year: int, max_year: int | None) -> list[int]:
    if max_year is None:
        max_year = dt.datetime.now().year
    if max_year < min_year:
        return []
    return list(range(min_year, max_year + 1))


def main_etl(argv: Sequence[str] | None = None) -> int:
    """ETL pipeline entry point."""
    parser = argparse.ArgumentParser(description="Vulnerability Radar ETL")
    parser.add_argument("--watchlist", default=None, help="Path to watchlist file (YAML or JSON)")
    parser.add_argument("--out", default="data/radar_data.json", help="Output JSON path")
    parser.add_argument("--report", default="data/radar_report.md", help="Output Markdown report path")
    parser.add_argument(
        "--min-year",
        type=int,
        default=_default_min_year(),
        help="Minimum CVE year to scan in bulk",
    )
    parser.add_argument("--max-year", type=int, default=None, help="Maximum CVE year to scan")
    parser.add_argument("--include-kev-outside-window", action="store_true")
    parser.add_argument("--skip-nvd", action="store_true", help="Skip NVD data feeds")
    parser.add_argument("--nvd-cache", default=None, help="Directory to cache NVD feeds")
    parser.add_argument(
        "--parallel", action="store_true", help="Download all data sources in parallel (requires aiohttp)"
    )
    parser.add_argument("--state", default="data/state.json", help="Path to state file")
    parser.add_argument("--list-vendors", nargs="?", const="", metavar="FILTER")
    parser.add_argument("--list-products", nargs="?", const="", metavar="FILTER")
    parser.add_argument("--validate-watchlist", action="store_true")
    # Search command
    parser.add_argument("--search", default=None, metavar="QUERY", help="Fuzzy search vendors/products")
    parser.add_argument(
        "--vendor-split", action="store_true",
        help="Also write per-vendor JSON files under data/vendors/",
    )
    args = parser.parse_args(argv)

    # Discovery commands
    if args.list_vendors is not None or args.list_products is not None or args.validate_watchlist:
        return _handle_discovery_commands(args)

    watchlist_path = args.watchlist if args.watchlist else find_watchlist()
    print(f"Using watchlist: {watchlist_path}")
    wl = load_merged_watchlist(Path(watchlist_path))
    session = requests_session()

    years = _years_to_process(args.min_year, args.max_year)
    nvd_cache = Path(args.nvd_cache) if args.nvd_cache else None

    if args.parallel:
        # ── Parallel downloads via aiohttp ────────────────────────────
        try:
            from .async_downloaders import download_all_parallel
        except ImportError:
            print("Warning: aiohttp not installed. Falling back to sequential downloads.")
            print("  Install with: pip install aiohttp>=3.9.0")
            args.parallel = False

    if args.parallel:
        print("Downloading all data sources in parallel...")
        dl = download_all_parallel(
            years=years,
            skip_nvd=bool(args.skip_nvd),
            nvd_cache_dir=nvd_cache,
        )
        kev_by_cve = dl.kev_by_cve
        epss_by_cve = dl.epss_by_cve
        patchthis_cves = dl.patchthis_cves
        nvd_by_cve = dl.nvd_by_cve
        zip_bytes = dl.zip_bytes
        if dl.errors:
            print(f"  ⚠️  {len(dl.errors)} download(s) had errors (continuing with partial data)")
        if not zip_bytes:
            print("❌ CVE List download failed — cannot continue without CVE data.")
            return 1
    else:
        # ── Sequential downloads via requests ─────────────────────────
        print("Downloading CISA KEV catalog...")
        kev_by_cve = download_cisa_kev(session)
        print(f"  Loaded {len(kev_by_cve)} KEV entries")

        print("Downloading EPSS scores...")
        epss_by_cve = download_epss(session)
        print(f"  Loaded {len(epss_by_cve)} EPSS scores")

        print("Downloading PatchThis intelligence...")
        patchthis_cves = download_patchthis(session)
        print(f"  Loaded {len(patchthis_cves)} PatchThis CVEs")

        nvd_by_cve: dict[str, dict[str, Any]] = {}
        if not args.skip_nvd:
            print("Downloading NVD data feeds...")
            nvd_by_cve = download_nvd_feeds(session, years, cache_dir=nvd_cache)
            print(f"  Loaded {len(nvd_by_cve)} CVEs from NVD feeds")
        else:
            print("Skipping NVD data feeds (--skip-nvd)")

        print("Downloading CVE List V5 bulk export...")
        zip_url = get_latest_cvelist_zip_url(session)
        zip_bytes = download_bytes(session, zip_url)

    extracted = download_and_extract_zip(zip_bytes)
    try:
        items = build_radar_data(
            extracted_dir=extracted,
            wl_vendors=wl.vendors,
            wl_products=wl.products,
            kev_by_cve=kev_by_cve,
            epss_by_cve=epss_by_cve,
            patchthis_cves=patchthis_cves,
            nvd_by_cve=nvd_by_cve,
            min_year=args.min_year,
            max_year=args.max_year,
            include_kev_outside_window=bool(args.include_kev_outside_window),
            severity_threshold=wl.thresholds.severity_threshold,
            epss_threshold=wl.thresholds.epss_threshold,
            min_cvss=wl.thresholds.min_cvss,
        )
    finally:
        shutil.rmtree(extracted, ignore_errors=True)

    items = items or []
    out_path = Path(args.out)

    if args.vendor_split:
        index = write_vendor_split(out_path.parent, items)
        n_vendors = index["vendor_count"]
        print(f"Wrote vendor split: {n_vendors} files under {out_path.parent / 'vendors/'}")
        # Write a slim stub so radar_data.json stays small
        write_radar_data(out_path, [], stub_message="Data split into per-vendor files. See radar_index.json.")
    else:
        write_radar_data(out_path, items)

    state_path = Path(args.state) if args.state else None
    write_markdown_report(Path(args.report), items, state_file=state_path)

    print(f"Wrote {len(items)} items to {args.out}")
    print(f"Wrote Markdown report to {args.report}")
    return 0


# ─── Notify CLI ───────────────────────────────────────────────────────────────


def _generate_demo_cve() -> dict[str, Any]:
    """Generate a realistic fake CVE for demo/conference purposes."""
    import random

    now = dt.datetime.now(dt.timezone.utc)
    due_date = (now + dt.timedelta(days=14)).strftime("%Y-%m-%d")

    return {
        "cve_id": "CVE-2099-DEMO",
        "description": (
            "A critical remote code execution vulnerability in the Apache HTTP Server's "
            "mod_vulnradar module allows unauthenticated attackers to execute arbitrary "
            "code via crafted HTTP headers. This is a DEMO vulnerability for presentation "
            "purposes at BSides Galway 2026."
        ),
        "cvss_score": 9.8,
        "probability_score": round(0.85 + random.random() * 0.14, 4),
        "active_threat": True,
        "in_patchthis": True,
        "watchlist_hit": True,
        "in_watchlist": True,
        "is_critical": True,
        "is_warning": False,
        "priority_label": "CRITICAL (Active Exploit in Stack)",
        "matched_terms": ["vendor:apache", "product:http_server"],
        "kev": {
            "cveID": "CVE-2099-DEMO",
            "vendorProject": "Apache",
            "product": "HTTP Server",
            "dueDate": due_date,
            "dateAdded": now.strftime("%Y-%m-%d"),
            "shortDescription": "Apache HTTP Server Remote Code Execution",
            "requiredAction": "Apply updates per vendor instructions.",
            "knownRansomwareCampaignUse": "Known",
        },
        "containers": {
            "cna": {
                "affected": [
                    {
                        "vendor": "Apache",
                        "product": "HTTP Server",
                        "versions": [{"version": "2.4.0", "status": "affected"}],
                    }
                ]
            }
        },
        "published": now.isoformat(),
        "references": [{"url": "https://example.com/cve-2099-demo"}],
    }


def _load_items(path: Path) -> list[dict[str, Any]]:
    # Support loading from a vendor-split directory via radar_index.json
    if path.is_dir():
        index_file = path / "radar_index.json"
        if index_file.exists():
            return load_vendor_split(path)
    if path.name == "radar_index.json" and path.exists():
        return load_vendor_split(path.parent)

    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return payload["items"]
    if isinstance(payload, list):
        return payload
    return []


def main_notify() -> int:
    """Notification pipeline entry point."""
    p = argparse.ArgumentParser(description="VulnRadar notifications")
    p.add_argument("--in", dest="inp", default="data/radar_data.json", help="Path to radar_data.json")
    p.add_argument("--max", dest="max_items", type=int, default=25, help="Max issues per run")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--state", dest="state_file", default="data/state.json")
    p.add_argument("--force", action="store_true")
    p.add_argument("--no-state", action="store_true")
    # Discord
    p.add_argument("--discord-webhook", dest="discord_webhook", default=os.environ.get("DISCORD_WEBHOOK_URL"))
    p.add_argument("--summary-every-run", action="store_true")
    p.add_argument("--discord-summary-only", action="store_true")
    p.add_argument("--discord-max", dest="discord_max", type=int, default=10)
    # Slack
    p.add_argument("--slack-webhook", dest="slack_webhook", default=os.environ.get("SLACK_WEBHOOK_URL"))
    p.add_argument("--slack-summary-only", action="store_true")
    p.add_argument("--slack-max", dest="slack_max", type=int, default=10)
    # Teams
    p.add_argument("--teams-webhook", dest="teams_webhook", default=os.environ.get("TEAMS_WEBHOOK_URL"))
    p.add_argument("--teams-summary-only", action="store_true")
    p.add_argument("--teams-max", dest="teams_max", type=int, default=10)
    # State commands
    p.add_argument("--reset-state", action="store_true")
    p.add_argument("--prune-state", type=int, metavar="DAYS")
    p.add_argument("--demo", action="store_true")
    p.add_argument("--weekly-summary", action="store_true")
    # Watchlist
    p.add_argument("--watchlist", default=None, help="Path to watchlist file (YAML or JSON)")
    # GitHub Projects v2
    p.add_argument("--project-url", dest="project_url", default=os.environ.get("VULNRADAR_PROJECT_URL"))
    args = p.parse_args()

    state_path = Path(args.state_file)

    # Handle state management commands
    if args.reset_state:
        if state_path.exists():
            state_path.unlink()
            print(f"✅ Deleted state file: {state_path}")
        else:
            print(f"ℹ️  State file doesn't exist: {state_path}")
        return 0

    if args.prune_state is not None:
        if not state_path.exists():
            print(f"ℹ️  State file doesn't exist: {state_path}")
            return 0
        prune_state = StateManager(state_path)
        stats_before = prune_state.get_stats()
        pruned = prune_state.prune_old_entries(days=args.prune_state)
        prune_state.save()
        print(f"✅ Pruned {pruned} CVEs not seen in {args.prune_state} days")
        print(f"   Before: {stats_before['total_tracked']} tracked")
        print(f"   After:  {prune_state.get_stats()['total_tracked']} tracked")
        return 0

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        raise SystemExit("GITHUB_REPOSITORY is required")
    if not token:
        raise SystemExit("GITHUB_TOKEN (or GH_TOKEN) is required")

    items = _load_items(Path(args.inp))

    # Load watchlist for baseline messages
    wl_path = Path(args.watchlist) if args.watchlist else Path(find_watchlist())
    wl = load_merged_watchlist(wl_path) if wl_path.exists() else WatchlistConfig()

    if args.demo:
        demo_cve = _generate_demo_cve()
        items.insert(0, demo_cve)
        print("\n🎭 DEMO MODE: Injected CVE-2099-DEMO (fake critical vulnerability)")
        print("   This CVE will trigger all notification channels.\n")

    # State management
    state: StateManager | None = None
    if not args.no_state:
        state = StateManager(Path(args.state_file))
        stats = state.get_stats()
        print(f"State loaded: {stats['total_tracked']} CVEs tracked, {stats['total_alerts_sent']} alerts sent")
        pruned = state.prune_old_entries(days=180)
        if pruned > 0:
            print(f"Pruned {pruned} CVEs not seen in 180 days")

    # Weekly summary
    if args.weekly_summary:
        print("\n📊 Creating weekly summary issue...")
        gh = GitHubIssueProvider(token=token, repo=repo)
        gh.create_weekly_summary(items, state)
        return 0

    # Detect changes
    changes_by_cve: dict[str, tuple] = {}
    for it in items:
        cve_id = str(it.get("cve_id") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        if state and not args.force:
            changes = state.detect_changes(cve_id, it)
            state.update_snapshot(cve_id, it)
            if changes:
                changes_by_cve[cve_id] = (it, changes)
        else:
            if bool(it.get("is_critical")):
                changes_by_cve[cve_id] = (it, [Change(cve_id=cve_id, change_type="NEW_CVE")])

    # Filter to critical with changes
    candidates: list[dict[str, Any]] = []
    for _cve_id, (it, _changes) in changes_by_cve.items():
        if bool(it.get("is_critical")):
            candidates.append(it)

    def _sort_key(it: dict[str, Any]) -> tuple:
        try:
            epss = float(it.get("probability_score") or 0.0)
        except Exception:
            epss = 0.0
        try:
            cvss = float(it.get("cvss_score") or 0.0)
        except Exception:
            cvss = 0.0
        return (
            1 if bool(it.get("is_critical")) else 0,
            1 if bool(it.get("active_threat")) else 0,
            epss,
            cvss,
        )

    candidates = sorted(candidates, key=_sort_key, reverse=True)

    if state and not args.force:
        if changes_by_cve:
            print(f"\n📊 Detected {len(changes_by_cve)} CVEs with changes:")
            for _cve_id, (_it, chs) in list(changes_by_cve.items())[:10]:
                for change in chs:
                    print(f"  {change}")
            if len(changes_by_cve) > 10:
                print(f"  ... and {len(changes_by_cve) - 10} more")
            print()
        else:
            print("\n✅ No new changes detected. Skipping notifications.\n")

    if state and not args.force and not changes_by_cve:
        if not args.dry_run:
            state.save()
            print(f"State saved to {args.state_file}")
        return 0

    is_first_run = state and state.data.get("last_run") is None and not args.force

    # ── GitHub Issues ─────────────────────────────────────────────────
    gh = GitHubIssueProvider(
        token=token,
        repo=repo,
        max_alerts=args.max_items,
        project_url=args.project_url,
    )

    if is_first_run and len(candidates) > 5:
        # First run: baseline summary only, no individual alerts
        print(f"\n🚀 First run detected! Creating baseline summary for {len(candidates)} items.")
        gh.send_baseline(items, candidates, repo, vendors=wl.vendors, products=wl.products)
    else:
        created, escalated = gh.send_all(candidates, changes_by_cve, dry_run=args.dry_run)

    # ── Webhook providers ─────────────────────────────────────────────
    alerted_channels: dict[str, list[str]] = {}

    providers = load_providers(
        discord_webhook=args.discord_webhook,
        slack_webhook=args.slack_webhook,
        teams_webhook=args.teams_webhook,
        discord_max=args.discord_max,
        slack_max=args.slack_max,
        teams_max=args.teams_max,
    )

    for provider in providers:
        name = provider.name
        print(f"Sending {name} notifications...")
        try:
            if is_first_run and len(candidates) > 5:
                # First run: baseline summary only, no individual alerts
                provider.send_baseline(items, candidates, repo, vendors=wl.vendors, products=wl.products)
                print(f"Sent {name} baseline summary (first run, {len(candidates)} items).")
            elif changes_by_cve or args.force or args.no_state:
                if args.summary_every_run:
                    provider.send_summary(items, repo, changes_by_cve if state else None)
                    print(f"Sent {name} summary.")

                summary_only_flag = getattr(args, f"{name}_summary_only", False)
                if not summary_only_flag:
                    max_per_provider = getattr(args, f"{name}_max", 10)
                    sent = 0
                    for it in candidates[:max_per_provider]:
                        cve_id = str(it.get("cve_id") or "").strip().upper()
                        item_changes = changes_by_cve.get(cve_id, (None, []))[1] if changes_by_cve else []
                        if args.dry_run:
                            print(f"DRY RUN: would send {name} alert for {cve_id}")
                        else:
                            rate_limit = {"discord": 0.5, "slack": 1.0, "teams": 0.5}.get(name, 0.5)
                            time.sleep(rate_limit)
                            provider.send_alert(it, item_changes)
                            print(f"Sent {name} alert for {cve_id}")
                            if cve_id not in alerted_channels:
                                alerted_channels[cve_id] = []
                            alerted_channels[cve_id].append(name)
                        sent += 1
                    print(f"Sent {sent} {name} alerts.")
        except Exception as e:
            print(f"{name} notification failed: {e}")

    # Save state
    if state and not args.dry_run:
        for cve_id, channels in alerted_channels.items():
            state.mark_alerted(cve_id, channels)
        state.save()
        stats = state.get_stats()
        print(f"State saved to {args.state_file} ({stats['total_tracked']} CVEs tracked)")

    return 0
