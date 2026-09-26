# Homework 2 RAG App

This guide explains how to run `app.py` on Windows. The app loads local documents, splits them into overlapping chunks, uses Gemini to create embeddings and answers, and retrieves relevant chunks locally.

## Requirements

- Python 3.10 or newer
- A Google Gemini API key from [Google AI Studio](https://aistudio.google.com/apikey)
- Internet access for Gemini API requests

Document text and questions are sent to Google's API for embeddings and answer generation. The document retrieval happens locally. The free API tier has usage limits.

## Set Up

Open PowerShell in the `homeworks\Homework2` directory and create a virtual environment:

```powershell
python -m venv .venv
```

Activate it and install the app dependencies:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-local.txt
```

If PowerShell blocks activation, run this in the same window and activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Set your API key in that PowerShell window. Replace the placeholder with your own key; never commit or share it:

```powershell
$env:GEMINI_API_KEY = "YOUR_GEMINI_API_KEY"
```

## Start the App

With the virtual environment active and API key set, run:

```powershell
python app.py
```

Open <http://127.0.0.1:5000> in your browser. Keep the PowerShell window open while using the app. To stop it, press `Ctrl+C`.

## Index Documents and Ask

The document folder initially points to `homeworks\Homework2\07_RAG\rag_data`. You can keep this folder or enter another local folder path in the app.

1. Enter the folder path and choose the chat and embedding models, or keep the defaults.
2. Select **Load documents and index** and wait for indexing to finish.
3. Enter a question and select **Ask**.

Supported file types are TXT, Markdown, CSV, HTML, PDF, and DOCX. PDF loading uses `pypdf`, installed by the requirements file. The app splits documents into 1,200-character chunks with 180 characters of overlap and shows the retrieved source filenames with each answer.

The default models are `gemini-3.8-flash` for answers and `gemini-embedding-2` for embeddings. The model fields in the app can be changed. To set defaults before starting the app, use:

```powershell
$env:GEMINI_CHAT_MODEL = "gemini-3.8-flash"
$env:GEMINI_EMBED_MODEL = "gemini-embedding-2"
```

The index is kept in memory and is cleared when the app stops, so index the folder again after restarting. If an API request returns `429 RESOURCE_EXHAUSTED`, check your Gemini API usage and rate limits, then try again later.