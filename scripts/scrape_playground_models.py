#!/usr/bin/env python3
"""Scrape https://build.nvidia.com/models for the complete NIM model registry.

The legacy ?pageSize=200&filters=... URL has returned an empty body since
2026-08; the current page server-renders the catalog in Next flight data:
  totalCount: N, "resources":[{"resourceId":"qc69jvmznzxy/<slug>",...}]
and model cards are <a href="/{publisher}/{slug}"> links. Each model's
playground page still inlines "nvcfFunctionId" + "namespace".

Only models whose playground page contains a valid UUID-shaped
"nvcfFunctionId" are reported as ok=true -- those are the ones that can
be called via the anonymous (hCaptcha-gated) predict endpoint.

Output (stdout): JSON with _meta and sorted `models` + `skipped` arrays.
Output (stderr): summary counts.
"""
import json
import re
import sys
import urllib.request
import concurrent.futures as cf
import time

MODELS_PAGE = "https://build.nvidia.com/models"
PLAYGROUND = "https://build.nvidia.com/{publisher}/{slug}/playground"
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

FNID_RE = re.compile(r'"nvcfFunctionId\\?":\\?"([a-f0-9-]{36})\\"?')
NS_RE = re.compile(r'"namespace\\?":\\?"([0-9a-z]+)\\"?')
# resource id embedded in flight data: "resourceId":"qc69jvmznzxy/<slug>"
RES_ID_RE = re.compile(r'qc69jvmznzxy/([A-Za-z0-9_.+\-~]+)')
# model card links: <a href="/publisher/slug">
LINK_RE = re.compile(r'href="/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.+\-~]+)"')


def fetch(url, timeout=25, tries=3):
    last = None
    for _ in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:
            last = e
            time.sleep(1)
    raise last  # noqa: BLE001


def get_models_from_page():
    """Fetch the Models page and return a dict {slug: publisher} for every
    model card rendered. Restricts to slugs that appear in the flight-data
    resources list; filters out non-model paths (/models/*, /explore/*, ...)."""
    html = fetch(MODELS_PAGE)
    slugs = set(RES_ID_RE.findall(html))
    pairs = {}
    for m in LINK_RE.finditer(html):
        pub = m.group(1)
        slug = m.group(2)
        if pub in ("models", "explore", "blueprints", "skills", "_next", ""):
            continue
        if slug in ("playground", "", "community"):
            continue
        if slugs and slug not in slugs:
            continue
        pairs.setdefault(slug, pub)
    return pairs


def probe_playground(publisher, slug):
    """Fetch the playground page and extract nvcfFunctionId + namespace."""
    try:
        html = fetch(PLAYGROUND.format(publisher=publisher, slug=slug), timeout=15)
    except Exception as e:
        return {"ok": False, "reason": str(e)}

    fn_m = FNID_RE.search(html)
    ns_m = NS_RE.search(html)

    if fn_m:
        fid = fn_m.group(1)
        return {"ok": True, "function_id": fid, "namespace": ns_m.group(1) if ns_m else ""}
    return {"ok": False, "reason": "no nvcfFunctionId in playground HTML"}


def main():
    sys.stderr.write("# Fetching models page...\n")
    slug_pub = get_models_from_page()
    sys.stderr.write(f"#   {len(slug_pub)} models found\n")

    sys.stderr.write("# Probing playground pages for NVCF ids...\n")
    results = []
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        fut_to_info = {ex.submit(probe_playground, pub, slug): (pub, slug)
                       for slug, pub in slug_pub.items()}

        for fut in cf.as_completed(fut_to_info):
            pub, slug = fut_to_info[fut]
            pdata = fut.result()
            entry = {
                "model": f"{pub}/{slug}",
                "slug": slug,
                "publisher": pub,
            }
            if pdata.get("ok"):
                entry["namespace"] = pdata["namespace"]
                entry["function_id"] = pdata["function_id"]
                entry["ok"] = True
                entry["source"] = "playground"
            else:
                entry["ok"] = False
                entry["reason"] = pdata.get("reason", "unknown")
            results.append(entry)

    ok = [r for r in results if r.get("ok")]
    bad = [r for r in results if not r.get("ok")]
    ok.sort(key=lambda r: r["model"])
    bad.sort(key=lambda r: r["model"])
    nss = sorted({r.get("namespace", "") for r in ok if r.get("namespace")})

    sys.stderr.write(f"# {len(ok)} playground models / {len(results)} total\n")
    sys.stderr.write(f"# namespaces: {nss}\n")
    sys.stderr.write("# skipped (no playground):\n")
    for r in bad:
        sys.stderr.write(f"#   {r['model']}: {r.get('reason')}\n")

    print(json.dumps({
        "_meta": {"count": len(ok), "total": len(results), "namespaces": nss},
        "models": ok,
        "skipped": bad,
    }, indent=2))


if __name__ == "__main__":
    main()
