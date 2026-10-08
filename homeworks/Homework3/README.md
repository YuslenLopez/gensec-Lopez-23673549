# ScamCat

ScamCat is a local LangChain agent that helps assess suspicious emails and texts. It uses `inspect_message` to find basic URL and urgency clues, and `python_repl` for simple calculations or text checks. It explains its findings but cannot prove a message is safe or a scam.

## Run

Install [uv](https://docs.astral.sh/uv/) and sync dependencies from this directory:

```powershell
uv sync
```

Create a `.env` file in this directory and add your Google AI Studio key. The file is ignored by Git:

```dotenv
GEMINI_API_KEY=your-key
GEMINI_MODEL=gemini-3.8-flash
```

Start the interactive conversation:

```powershell
uv run python app.py
```

Paste a message, then ask follow-up questions. Type `quit` or `exit` to stop. To start with a message from the command line, use `uv run python app.py "Your account needs verification"`.

## Example Prompts

- `Check this message for scam warning signs: "You won $1,000! Click http://bit.ly/claim now."`
- `Check this text: "Your bank account is locked. Verify now at http://192.0.2.44/login." Also, use Python to calculate 12% of $250.`
- `Check this message: "Buy four $50 gift cards and send me the codes right away." Use Python to calculate their total cost.`

Paste message text only and remove private information. The app does not open links or check their online reputation. `python_repl` executes code and is not a security sandbox; keep the app local and do not use it with untrusted users.