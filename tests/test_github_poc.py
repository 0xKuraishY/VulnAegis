from unittest.mock import MagicMock

from app.connectors.github_poc import GithubPocConnector

SEARCH_RESPONSE = {
    "items": [
        {
            "full_name": "someuser/CVE-2026-1234-poc",
            "name": "CVE-2026-1234-poc",
            "description": "PoC for a critical RCE",
            "html_url": "https://github.com/someuser/CVE-2026-1234-poc",
            "stargazers_count": 42,
        },
        {
            # Casse mixte volontaire : doit se normaliser vers le même ID que ci-dessus si jamais
            # rencontré, et ne jamais créer de doublon.
            "full_name": "otheruser/exploit-writeup",
            "name": "exploit-writeup",
            "description": "Write-up for cve-2026-1234 with working exploit",
            "html_url": "https://github.com/otheruser/exploit-writeup",
            "stargazers_count": 3,
        },
        {
            "full_name": "someuser/unrelated-tool",
            "name": "unrelated-tool",
            "description": "Not a PoC at all",
            "html_url": "https://github.com/someuser/unrelated-tool",
            "stargazers_count": 1,
        },
    ]
}


def _session_returning(payload):
    session = MagicMock()
    resp = MagicMock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    session.get.return_value = resp
    return session


def test_fetch_recent_extracts_and_normalizes_cve_ids():
    session = _session_returning(SEARCH_RESPONSE)
    connector = GithubPocConnector(session=session)

    discoveries = connector.fetch_recent()

    cve_ids = {d["cve_id"] for d in discoveries}
    assert cve_ids == {"CVE-2026-1234"}  # les deux repos matchent la même CVE, normalisée en majuscules
    assert len(discoveries) == 2  # un par repo, pas dédupliqué entre repos différents
    urls = {d["url"] for d in discoveries}
    assert urls == {
        "https://github.com/someuser/CVE-2026-1234-poc",
        "https://github.com/otheruser/exploit-writeup",
    }


def test_fetch_recent_skips_repos_without_a_cve_id():
    session = _session_returning({"items": [SEARCH_RESPONSE["items"][2]]})
    connector = GithubPocConnector(session=session)
    assert connector.fetch_recent() == []


def test_fetch_recent_queries_current_and_previous_year_only():
    session = _session_returning({"items": []})
    GithubPocConnector(session=session).fetch_recent()
    assert session.get.call_count == 2  # YEARS_BACK=1 -> année courante + précédente
