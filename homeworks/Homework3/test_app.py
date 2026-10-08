"""Tests for deterministic message inspection behavior."""

from app import analyze_message


def test_analyze_message_flags_basic_url_clues() -> None:
	"""Report simple indicators without claiming the message is malicious."""
	result = analyze_message("Urgent action: visit http://192.0.2.1/login now.")

	assert result["links"][0]["domain"] == "192.0.2.1"
	assert any("numeric IP address" in signal for signal in result["signals"])
	assert any("HTTP rather than HTTPS" in signal for signal in result["signals"])
	assert any("urgent wording" in signal for signal in result["signals"])
	assert "not a determination" in result["note"]


def test_analyze_message_handles_text_without_links() -> None:
	"""Return an empty link list for a message without a URL."""
	result = analyze_message("Hi, the study group meets at noon.")

	assert result["links"] == []
	assert result["signals"] == []