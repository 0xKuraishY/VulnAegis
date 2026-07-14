from datetime import datetime, timezone
from unittest.mock import MagicMock

from app.connectors.cisa_kev import CisaKevConnector
from app.connectors.github_advisories import GitHubAdvisoriesConnector
from app.connectors.nvd import NvdConnector

NVD_SAMPLE = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-1234",
                "published": "2026-07-01T00:00:00.000",
                "lastModified": "2026-07-02T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "A critical RCE in Example Server"}],
                "metrics": {
                    "cvssMetricV31": [
                        {"type": "Primary", "cvssData": {"baseScore": 9.8, "vectorString": "AV:N", "baseSeverity": "CRITICAL"}}
                    ]
                },
                "references": [
                    {"url": "https://example.com/advisory", "tags": ["Third Party Advisory"]},
                    {"url": "https://example.com/patch", "tags": ["Patch", "Vendor Advisory"]},
                ],
                "configurations": [
                    {"nodes": [{"cpeMatch": [
                        {"criteria": "cpe:2.3:a:examplevendor:exampleproduct:1.0:*:*:*:*:*:*:*"},
                        {"criteria": "cpe:2.3:a:examplevendor:exampleproduct:2.0:*:*:*:*:*:*:*"},
                    ]}]}
                ],
                "weaknesses": [
                    {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-79"}]},
                    {"source": "cna", "type": "Secondary", "description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]},
                ],
            }
        }
    ],
}

KEV_SAMPLE = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-5678",
            "vendorProject": "Example Vendor",
            "product": "Example Product",
            "shortDescription": "Actively exploited buffer overflow",
            "dateAdded": "2026-07-01",
            "dueDate": "2026-07-15",
            "knownRansomwareCampaignUse": "Unknown",
        }
    ]
}

GHSA_SAMPLE = [
    {
        "cve_id": "CVE-2026-9999",
        "summary": "Prototype pollution in example-pkg",
        "severity": "high",
        "cvss": {"score": 7.5, "vector_string": "AV:N"},
        "published_at": "2026-07-01T00:00:00Z",
        "updated_at": "2026-07-02T00:00:00Z",
        "html_url": "https://github.com/advisories/GHSA-xxxx",
        "references": [],
        "vulnerabilities": [{"package": {"name": "example-pkg", "ecosystem": "npm"}}],
    }
]


def test_nvd_connector_normalizes_response():
    session = MagicMock()
    session.get.return_value.json.return_value = NVD_SAMPLE
    session.get.return_value.raise_for_status.return_value = None

    connector = NvdConnector(session=session)
    results = connector.fetch_since(datetime.now(timezone.utc))

    assert len(results) == 1
    cve = results[0]
    assert cve.cve_id == "CVE-2026-1234"
    assert cve.cvss_score == 9.8
    assert cve.severity == "CRITICAL"
    assert cve.vendor == "examplevendor"
    assert cve.product == "exampleproduct"
    assert cve.references == ["https://example.com/advisory", "https://example.com/patch"]
    assert cve.cwe_ids == ["CWE-79"]  # "NVD-CWE-noinfo" ne matche pas le pattern CWE-\d+, filtré
    assert cve.affected_cpes == [
        "cpe:2.3:a:examplevendor:exampleproduct:1.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:examplevendor:exampleproduct:2.0:*:*:*:*:*:*:*",
    ]
    assert cve.references_meta == [
        {"url": "https://example.com/advisory", "tags": ["Third Party Advisory"]},
        {"url": "https://example.com/patch", "tags": ["Patch", "Vendor Advisory"]},
    ]


def test_cisa_kev_connector_marks_is_kev():
    session = MagicMock()
    session.get.return_value.json.return_value = KEV_SAMPLE
    session.get.return_value.raise_for_status.return_value = None

    connector = CisaKevConnector(session=session)
    results = connector.fetch_since(None)

    assert len(results) == 1
    cve = results[0]
    assert cve.cve_id == "CVE-2026-5678"
    assert cve.is_kev is True
    assert cve.kev_date_added is not None


def test_cisa_kev_connector_filters_by_since():
    session = MagicMock()
    session.get.return_value.json.return_value = KEV_SAMPLE
    session.get.return_value.raise_for_status.return_value = None

    connector = CisaKevConnector(session=session)
    since = datetime(2026, 12, 1, tzinfo=timezone.utc)
    results = connector.fetch_since(since)

    assert results == []


def test_github_advisories_connector_normalizes_and_skips_missing_cve():
    session = MagicMock()
    resp = MagicMock()
    resp.json.return_value = GHSA_SAMPLE
    resp.raise_for_status.return_value = None
    resp.links = {}
    session.get.return_value = resp

    connector = GitHubAdvisoriesConnector(session=session)
    results = connector.fetch_since(None)

    assert len(results) == 1
    cve = results[0]
    assert cve.cve_id == "CVE-2026-9999"
    assert cve.severity == "HIGH"
    assert cve.vendor == "npm"
    assert cve.product == "example-pkg"
