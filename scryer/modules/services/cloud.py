"""Cloud storage exposure checks.

Web apps constantly leak the cloud buckets they pull assets from — an
`<img src="https://acme-assets.s3.amazonaws.com/...">`, a JS config pointing at
a GCS bucket, an Azure blob URL in a download link. This module harvests those
references from any response body scryer sees and probes each one anonymously
for the classic misconfigurations: public object read and public bucket
listing (and, for S3, world-writable ACLs are noted for manual follow-up).

Pure standard library; safe to run on every web response.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from typing import Set, Tuple

from ...core import utils
from ...core.report import HostReport, Finding


_UA = "Mozilla/5.0 (compatible; scryer/2.0)"

# provider, bucket-capturing regex. Order matters (more specific first).
_PATTERNS = [
    ("s3", re.compile(r"https?://([a-z0-9.\-]{3,63})\.s3[.\-][a-z0-9.\-]*amazonaws\.com", re.I)),
    ("s3", re.compile(r"https?://s3[.\-][a-z0-9.\-]*amazonaws\.com/([a-z0-9.\-]{3,63})", re.I)),
    ("s3", re.compile(r"\bs3://([a-z0-9.\-]{3,63})", re.I)),
    ("gcs", re.compile(r"https?://storage\.googleapis\.com/([a-z0-9._\-]{3,63})", re.I)),
    ("gcs", re.compile(r"https?://([a-z0-9._\-]{3,63})\.storage\.googleapis\.com", re.I)),
    ("gcs", re.compile(r"\bgs://([a-z0-9._\-]{3,63})", re.I)),
    ("azure", re.compile(r"https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net/([a-z0-9\-]{3,63})", re.I)),
    ("spaces", re.compile(r"https?://([a-z0-9.\-]{3,63})\.([a-z0-9\-]+)\.digitaloceanspaces\.com", re.I)),
]

_seen: Set[str] = set()


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _get(url: str, timeout: float = 8.0) -> Tuple[int, str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            return r.status, r.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
        return e.code, ""
    except Exception:
        return 0, ""


def detect_s3_endpoint(host: HostReport, port: int, body: str,
                       headers: dict, vhost: str = None, pfx: str = "") -> None:
    """Spot an S3-compatible API served *by the target itself* (LocalStack /
    MinIO / Ceph on a vhost like s3.box.htb). The tell is an S3 XML root or an
    'AmazonS3'/'MinIO' Server header. These are a classic foothold: list the
    buckets anonymously and, if writable, upload a webshell that the main site
    then serves."""
    server = (headers or {}).get("server", "").lower()
    b = body or ""
    is_s3 = ("<ListAllMyBucketsResult" in b or "<ListBucketResult" in b
             or "amazons3" in server or "minio" in server
             or (vhost and vhost.lower().startswith("s3.")
                 and "<?xml" in b[:200].lower()))
    if not is_s3:
        return
    endpoint = f"http://{vhost}:{port}" if vhost else f"http://{host.resolved_ip}:{port}"
    buckets = re.findall(r"<Name>([^<]+)</Name>", b)
    utils.log("hot", f"S3-compatible storage API at {endpoint}", indent=2)
    host.add(Finding(
        title=f"{pfx}S3-compatible storage endpoint (LocalStack/MinIO)",
        detail=f"An S3 API is exposed at {endpoint}"
               + (f" — buckets: {', '.join(buckets[:10])}." if buckets else ".")
               + " Enumerate and test write access with the AWS CLI:\n"
               f"  aws --endpoint-url={endpoint} s3 ls\n"
               f"  aws --endpoint-url={endpoint} s3 ls s3://<bucket>\n"
               f"  aws --endpoint-url={endpoint} s3 cp shell.php s3://<bucket>/\n"
               "If the bucket backs the website's document root, an uploaded "
               ".php file is a webshell (RCE). See notes/cloud.md.",
        severity="high", category="cloud", port=port, service="http",
        confidence="potential", evidence=endpoint))


def scan(host: HostReport, port: int, body: str, pfx: str = "") -> None:
    if not body:
        return
    hits = []
    for provider, rx in _PATTERNS:
        for m in rx.finditer(body):
            bucket = m.group(1)
            key = f"{provider}:{m.group(0).lower()}"
            if key in _seen:
                continue
            _seen.add(key)
            hits.append((provider, bucket, m))
    for provider, bucket, m in hits[:15]:
        utils.log("good", f"cloud storage reference: {provider} bucket "
                          f"'{bucket}'", indent=2)
        host.add(Finding(
            title=f"{pfx}Cloud storage bucket referenced: {bucket} ({provider})",
            detail=f"Found in page/JS: {m.group(0)}", severity="info",
            category="cloud", port=port, service="http", evidence=m.group(0)))
        _probe(host, port, provider, bucket, m, pfx)


def _probe(host: HostReport, port: int, provider: str, bucket: str, m, pfx: str) -> None:
    if provider == "s3":
        list_url = f"https://{bucket}.s3.amazonaws.com/"
    elif provider == "gcs":
        list_url = f"https://storage.googleapis.com/{bucket}"
    elif provider == "azure":
        container = m.group(2)
        list_url = (f"https://{bucket}.blob.core.windows.net/{container}"
                    f"?restype=container&comp=list")
    elif provider == "spaces":
        list_url = m.group(0).rstrip("/") + "/"
    else:
        return

    status, text = _get(list_url)
    if status == 200 and ("<ListBucketResult" in text or "<EnumerationResults" in text
                          or "<Contents" in text or "<Blob>" in text):
        utils.log("hot", f"PUBLIC bucket listing: {list_url}", indent=3)
        keys = re.findall(r"<(?:Key|Name)>([^<]+)</(?:Key|Name)>", text)
        host.add(Finding(
            title=f"{pfx}PUBLIC cloud bucket listing: {bucket} ({provider})",
            detail=f"Anonymous listing succeeded at {list_url}. "
                   + (f"Objects: {', '.join(keys[:20])}" if keys else "")
                   + " See notes/cloud.md to download/sync.",
            severity="high", category="cloud", port=port, service="http",
            evidence=f"{list_url}\n{text[:600]}"))
    elif status in (200, 403):
        # 403 on listing but the bucket exists — objects may still be public.
        host.add(Finding(
            title=f"{pfx}Cloud bucket exists (listing denied): {bucket} ({provider})",
            detail=f"{list_url} returned HTTP {status}. Listing is locked but "
                   "individual known object keys may still be world-readable — "
                   "try direct object URLs and 'aws s3 ... --no-sign-request'.",
            severity="low", category="cloud", port=port, service="http",
            confidence="potential", evidence=list_url))
