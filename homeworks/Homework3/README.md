# Suspicious Message Coach

A small local LangChain agent that explains possible warning signs in a pasted email or text message. It reports simple URL and urgency clues; it does not verify whether a message is safe or malicious.

## Setup

Install [uv](https://docs.astral.sh/uv/), then from this directory run:

```powershell
uv sync
```

The `.env` file is ignored by Git. Add your Google AI Studio key there, using `.env.example` as a template:

```text
GOOGLE_API_KEY=your-key
GEMINI_MODEL=gemini-3.8-flash
```

Run the app and tests with:

```powershell
uv run python app.py
uv run pytest
```

You can also pass a message as a quoted command-line argument: `uv run python app.py "Your account needs verification"`.
The app stays open for follow-up questions; type `quit` or `exit` to end the conversation.

## Safety notes

Paste message text only; remove personal or confidential information first. The app does not open links or check online reputation. Its PythonREPL tool executes Python code and is not a security sandbox, so keep this project local and do not expose it to untrusted users or deploy it as a public service.