import gzip
from unittest.mock import MagicMock

from app.enrichment.epss import EpssEnricher

CSV_SAMPLE = (
    "#model_version:v2023.03.01,score_date:2026-07-01T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.94520,0.99991\n"
    "CVE-2026-0001,0.00073,0.30411\n"
)


def test_epss_enricher_parses_gzipped_csv_and_skips_comment_line():
    session = MagicMock()
    session.get.return_value.content = gzip.compress(CSV_SAMPLE.encode("utf-8"))
    session.get.return_value.raise_for_status.return_value = None

    index = EpssEnricher(session=session).fetch_index()

    assert index["CVE-2021-44228"] == (0.9452, 0.99991)
    assert index["CVE-2026-0001"] == (0.00073, 0.30411)
    assert len(index) == 2


def test_epss_enricher_handles_already_decompressed_content():
    session = MagicMock()
    session.get.return_value.content = CSV_SAMPLE.encode("utf-8")
    session.get.return_value.raise_for_status.return_value = None

    index = EpssEnricher(session=session).fetch_index()
    assert index["CVE-2021-44228"] == (0.9452, 0.99991)
