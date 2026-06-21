"""Tests for path relevance scoring."""

from software_butcher.core.path_relevance import (
    detect_default_stack_landing,
    is_noise_path,
    score_path,
    should_queue_path,
)


def test_xampp_paths_are_noise():
    assert is_noise_path("http://example.com/dashboard/faq.html")
    assert is_noise_path("http://example.com/dashboard/howto.html")
    assert is_noise_path("http://example.com/dashboard/Images")
    assert not is_noise_path("http://example.com/hall")


def test_ctf_filesystem_paths_blocked():
    from software_butcher.core.path_relevance import is_ctf_filesystem_path, is_hypothesis_path_allowed

    assert is_ctf_filesystem_path("/home/user/user.txt")
    assert is_ctf_filesystem_path("/root/root.txt")
    assert is_ctf_filesystem_path("http://example.com/home/user/user.txt")
    assert not is_hypothesis_path_allowed("/home/user/user.txt")
    assert is_hypothesis_path_allowed(
        "/home/user/user.txt",
        metadata={"organically_discovered": True},
    )


def test_hall_scores_high():
    assert score_path("http://hallbooking.srmrmp.edu.in/hall") >= 0.9
    assert should_queue_path("http://hallbooking.srmrmp.edu.in/hall")


def test_dashboard_docs_score_low():
    assert score_path("http://example.com/dashboard/faq.html") < 0.2
    assert not should_queue_path("http://example.com/dashboard/faq.html")


def test_detect_xampp_landing():
    result = detect_default_stack_landing(
        title="Welcome to XAMPP",
        body="XAMPP for Linux",
        final_url="http://example.com/dashboard/",
    )
    assert result["detected"] is True
    assert result["stack"] == "xampp_default"


def test_phpmyadmin_and_phpinfo_no_path_boost():
    assert score_path("http://example.com/phpmyadmin/") < 0.93
    assert score_path("http://example.com/dashboard/phpinfo.php") < 0.95
