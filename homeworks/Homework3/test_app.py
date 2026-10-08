"""Tests for deterministic message inspection behavior."""

from types import SimpleNamespace

from app import analyze_message, format_text_content, format_tool_call_details
from app import get_used_tool_names


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


def test_format_text_content_omits_provider_metadata() -> None:
	"""Keep text blocks but omit signature metadata from model content."""
	result = format_text_content(
		[
			{"type": "text", "text": "This is likely a scam."},
			{"extras": {"signature": "hidden metadata"}},
		]
	)

	assert result == "This is likely a scam."
	assert "signature" not in result


def test_get_used_tool_names_returns_tools_called_this_turn() -> None:
	"""List called tools once, including names from tool-call messages."""
	messages = [
		SimpleNamespace(
			name=None,
			tool_calls=[{"name": "inspect_message"}, {"name": "python_repl"}],
		),
		SimpleNamespace(name="inspect_message", tool_calls=[]),
	]

	assert get_used_tool_names(messages) == ["inspect_message", "python_repl"]


def test_format_tool_call_details_shows_tool_inputs() -> None:
	"""Display a tool's name and its arguments in a readable line."""
	messages = [
		SimpleNamespace(
			tool_calls=[
				{
					"name": "inspect_message",
					"args": {"message": "Urgent: click http://bit.ly/claim"},
				}
			]
		)
	]

	assert format_tool_call_details(messages) == [
		'inspect_message input: {"message": "Urgent: click http://bit.ly/claim"}'
	]