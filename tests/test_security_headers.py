def test_security_headers_present_on_api_response(client):
    resp = client.get("/api/cves/stats")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert "geolocation=()" in resp.headers["Permissions-Policy"]
    assert "max-age=" in resp.headers["Strict-Transport-Security"]
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_docs_paths_are_exempt_from_csp(client):
    resp = client.get("/openapi.json")
    assert "Content-Security-Policy" not in resp.headers
    # Les autres en-têtes restent appliqués partout.
    assert resp.headers["X-Frame-Options"] == "DENY"
