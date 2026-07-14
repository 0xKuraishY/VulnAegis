from app.rate_limit import check_rate_limit, reset_rate_limit


def test_allows_up_to_max_attempts_then_blocks():
    reset_rate_limit("k1")
    for _ in range(3):
        assert check_rate_limit("k1", max_attempts=3, window_seconds=60) is True
    assert check_rate_limit("k1", max_attempts=3, window_seconds=60) is False


def test_different_keys_are_independent():
    reset_rate_limit("k2a")
    reset_rate_limit("k2b")
    for _ in range(3):
        assert check_rate_limit("k2a", max_attempts=3, window_seconds=60) is True
    assert check_rate_limit("k2a", max_attempts=3, window_seconds=60) is False
    # k2b n'a jamais été appelé : pas affecté par le blocage de k2a.
    assert check_rate_limit("k2b", max_attempts=3, window_seconds=60) is True


def test_old_attempts_expire_out_of_the_window():
    reset_rate_limit("k3")
    assert check_rate_limit("k3", max_attempts=1, window_seconds=0.05) is True
    assert check_rate_limit("k3", max_attempts=1, window_seconds=0.05) is False
    import time
    time.sleep(0.1)
    assert check_rate_limit("k3", max_attempts=1, window_seconds=0.05) is True
