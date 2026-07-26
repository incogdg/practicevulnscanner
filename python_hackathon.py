import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

try:
    import nmap  # type: ignore
except ImportError:
    nmap = None

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_RATE_LIMIT_SECONDS = 6
_last_nvd_request_time = 0.0


ServiceMap = Dict[int, Dict[str, str]]
Finding = Dict[str, Any]


def scan_services(
    target_ip: str,
    use_nmap: bool = True,
    demo_mode: bool = False,
) -> ServiceMap:
    """
    Discover open TCP ports and detect their services.

    Only scan systems you own or have explicit permission to assess.
    """
    if demo_mode:
        print("Demo mode enabled; using sample service information.")
        return {
            22: {
                "name": "ssh",
                "product": "OpenSSH",
                "version": "8.9",
            },
            80: {
                "name": "http",
                "product": "nginx",
                "version": "1.18.0",
            },
            443: {
                "name": "https",
                "product": "Apache httpd",
                "version": "2.4.52",
            },
        }

    if not use_nmap or nmap is None:
        raise RuntimeError(
            "python-nmap is unavailable. Install python-nmap and the Nmap "
            "application, or run with demo_mode=True."
        )

    scanner = nmap.PortScanner()

    try:
        scanner.scan(
            hosts=target_ip,
            arguments="-sV --version-light -T3",
        )
    except Exception as exc:
        raise RuntimeError(f"Nmap scan failed: {exc}") from exc

    services: ServiceMap = {}

    for host in scanner.all_hosts():
        tcp_results = scanner[host].get("tcp", {})

        for port, info in tcp_results.items():
            if info.get("state") != "open":
                continue

            services[int(port)] = {
                "name": str(info.get("name") or "unknown"),
                "product": str(info.get("product") or "unknown"),
                "version": str(info.get("version") or "unknown"),
            }

    return dict(sorted(services.items()))


def build_cpe(product: str, version: str) -> Optional[str]:
    """Build a simple NVD CPE 2.3 string from service product and version."""
    normalized = product.strip().lower()
    normalized = normalized.replace(" ", ":")

    if not normalized or normalized == "unknown":
        return None

    if version and version != "unknown":
        version_segment = version.strip().lower()
    else:
        version_segment = "*"

    return f"cpe:2.3:a:{normalized}:{normalized}:{version_segment}:*:*:*:*:*:*:*"


def throttle_nvd_request() -> None:
    """Enforce a conservative NVD request rate limit."""
    global _last_nvd_request_time
    elapsed = time.monotonic() - _last_nvd_request_time
    if elapsed < NVD_RATE_LIMIT_SECONDS:
        time.sleep(NVD_RATE_LIMIT_SECONDS - elapsed)
    _last_nvd_request_time = time.monotonic()


def fetch_vulnerability_data(
    product: str,
    version: str,
    results_per_page: int = 5,
) -> Dict[str, Any]:
    """Query NVD for confirmed product matches using CPE filtering."""
    if not product or product == "unknown":
        return {
            "matches": [],
            "error": None,
        }

    cpe_name = build_cpe(product, version)
    if cpe_name is None:
        return {
            "matches": [],
            "error": None,
        }

    throttle_nvd_request()

    parameters = urllib.parse.urlencode(
        {
            "cpeName": cpe_name,
            "resultsPerPage": max(1, min(results_per_page, 20)),
        }
    )

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{parameters}"

    request_headers = {
        "User-Agent": "authorised-security-scanner/0.2",
        "Accept": "application/json",
    }

    if NVD_API_KEY:
        request_headers["apiKey"] = NVD_API_KEY

    request = urllib.request.Request(url, headers=request_headers)

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.load(response)

    except urllib.error.HTTPError as exc:
        return {
            "matches": [],
            "error": f"NVD HTTP error {exc.code}",
        }

    except urllib.error.URLError as exc:
        return {
            "matches": [],
            "error": f"NVD connection error: {exc.reason}",
        }

    except (TimeoutError, json.JSONDecodeError) as exc:
        return {
            "matches": [],
            "error": f"NVD response error: {exc}",
        }

    return {
        "matches": payload.get("vulnerabilities", []),
        "error": None,
    }


def extract_cve_id(vulnerability: Optional[Dict[str, Any]]) -> Optional[str]:
    """Extract the CVE identifier from an NVD vulnerability record."""
    if not vulnerability:
        return None

    cve = vulnerability.get("cve", {})

    if not isinstance(cve, dict):
        return None

    cve_id = cve.get("id")
    return str(cve_id) if cve_id else None


def extract_cvss(vulnerability: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract the preferred CVSS score and severity."""
    result = {
        "severity": "unknown",
        "score": None,
        "version": None,
    }

    if not vulnerability:
        return result

    metrics = vulnerability.get("cve", {}).get("metrics", {})

    if not isinstance(metrics, dict):
        return result

    metric_groups = (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    )

    for metric_key, cvss_version in metric_groups:
        entries = metrics.get(metric_key, [])

        if not isinstance(entries, list):
            continue

        for metric in entries:
            if not isinstance(metric, dict):
                continue

            cvss_data = metric.get("cvssData", {})

            if not isinstance(cvss_data, dict):
                cvss_data = {}

            severity = (
                metric.get("baseSeverity")
                or metric.get("severity")
                or cvss_data.get("baseSeverity")
            )

            score = cvss_data.get("baseScore")

            if severity:
                result["severity"] = str(severity).lower()
            elif isinstance(score, (int, float)):
                if score >= 9:
                    result["severity"] = "critical"
                elif score >= 7:
                    result["severity"] = "high"
                elif score >= 4:
                    result["severity"] = "medium"
                else:
                    result["severity"] = "low"

            result["score"] = score
            result["version"] = cvss_version
            return result

    return result


def identify_vulnerabilities(services: ServiceMap) -> List[Finding]:
    """
    Generate potential CVE matches.

    Keyword results are candidates, not confirmation that the host is affected.
    """
    findings: List[Finding] = []

    for port, service in services.items():
        product = service.get("product", "unknown")
        service_name = service.get("name", "unknown")
        version = service.get("version", "unknown")

        lookup = fetch_vulnerability_data(
            product=product,
            version=version,
            results_per_page=5,
        )

        matches = lookup["matches"]
        api_error = lookup["error"]

        if api_error:
            findings.append(
                {
                    "port": port,
                    "service_name": service_name,
                    "product": product,
                    "service_version": version,
                    "status": "lookup_error",
                    "severity": "unknown",
                    "cvss_score": None,
                    "cvss_version": None,
                    "cve_id": None,
                    "candidate_count": 0,
                    "api_error": api_error,
                }
            )
            continue

        if not matches:
            findings.append(
                {
                    "port": port,
                    "service_name": service_name,
                    "product": product,
                    "service_version": version,
                    "status": "no_candidate_found",
                    "severity": "unknown",
                    "cvss_score": None,
                    "cvss_version": None,
                    "cve_id": None,
                    "candidate_count": 0,
                    "api_error": None,
                }
            )
            continue

        first_match = matches[0]
        cvss = extract_cvss(first_match)

        findings.append(
            {
                "port": port,
                "service_name": service_name,
                "product": product,
                "service_version": version,
                "status": "potential_match",
                "severity": cvss["severity"],
                "cvss_score": cvss["score"],
                "cvss_version": cvss["version"],
                "cve_id": extract_cve_id(first_match),
                "candidate_count": len(matches),
                "api_error": None,
            }
        )

    return findings


def recommended_action(severity: str, status: str) -> str:
    if status == "lookup_error":
        return "Retry lookup"

    if status == "no_candidate_found":
        return "Review manually"

    if severity == "critical":
        return "Immediate review"

    if severity == "high":
        return "Escalate"

    if severity == "medium":
        return "Schedule investigation"

    if severity == "low":
        return "Document and monitor"

    return "Manual validation required"


def generate_report(findings: List[Finding]) -> None:
    print("\nPotential vulnerability report")
    print("=" * 80)

    for finding in findings:
        product = finding["product"]
        version = finding["service_version"]

        print(
            f"Port {finding['port']}: "
            f"{product} {version} "
            f"({finding['service_name']})"
        )

        print(f"  Status: {finding['status']}")
        print(f"  Potential CVE: {finding['cve_id'] or 'None'}")
        print(f"  Potential severity: {finding['severity']}")
        print(f"  CVSS score: {finding['cvss_score']}")
        print(f"  Candidate results: {finding['candidate_count']}")

        if finding["api_error"]:
            print(f"  Lookup error: {finding['api_error']}")

        print(
            "  Recommended action: "
            f"{recommended_action(finding['severity'], finding['status'])}"
        )
        print("-" * 80)


def decide_next_action(findings: List[Finding]) -> str:
    severities = {
        finding["severity"]
        for finding in findings
        if finding["status"] == "potential_match"
    }

    if "critical" in severities or "high" in severities:
        return "ALERT: validate high-priority candidate matches"

    if "medium" in severities:
        return "INVESTIGATE: validate medium-priority candidate matches"

    if any(finding["status"] == "lookup_error" for finding in findings):
        return "RETRY: one or more NVD lookups failed"

    return "CONTINUE: no high-priority candidate matches found"


def count_high_priority_candidates(findings: List[Finding]) -> int:
    return sum(
        1
        for finding in findings
        if finding["status"] == "potential_match"
        and finding["severity"] in {"critical", "high"}
    )


def main(
    target_ip: str = "127.0.0.1",
    demo_mode: bool = False,
) -> None:
    try:
        services = scan_services(
            target_ip=target_ip,
            demo_mode=demo_mode,
        )
    except RuntimeError as exc:
        print(f"Scan error: {exc}")
        return

    if not services:
        print("No open TCP services were discovered.")
        return

    findings = identify_vulnerabilities(services)
    generate_report(findings)

    print(decide_next_action(findings))
    print(
        "High or critical potential matches: "
        f"{count_high_priority_candidates(findings)}"
    )
    print(
        "\nWarning: NVD keyword matches are unverified candidates. "
        "Confirm the exact product, version and affected version range "
        "before reporting a vulnerability."
    )


if __name__ == "__main__":
    # Change only to an authorised lab target.
    main(target_ip="192.168.213.120", demo_mode=False)