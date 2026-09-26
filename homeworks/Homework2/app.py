"""A small local RAG app using Google's Gemini API for embeddings and generation."""

from __future__ import annotations

import math
import os
import re
import xml.etree.ElementTree as ET
import zipfile
from html.parser import HTMLParser
from pathlib import Path

from flask import Flask, render_template_string, request


APP_DIR = Path(__file__).resolve().parent
DEFAULT_DOCUMENT_DIR = APP_DIR / "07_RAG" / "rag_data"
DEFAULT_CHAT_MODEL = os.getenv("GEMINI_CHAT_MODEL", "gemini-3.8-flash")
DEFAULT_EMBED_MODEL = os.getenv("GEMINI_EMBED_MODEL", "gemini-embedding-2")
SUPPORTED_EXTENSIONS = {".txt", ".md", ".csv", ".html", ".htm", ".pdf", ".docx"}
CHUNK_SIZE = 1200
CHUNK_OVERLAP = 180
TOKEN_PATTERN = re.compile(r"\w+|[^\w\s]", re.UNICODE)

app = Flask(__name__)
indexed_chunks: list[dict[str, str]] = []
indexed_vectors: list[list[float]] = []
chat_model = DEFAULT_CHAT_MODEL
embed_model = DEFAULT_EMBED_MODEL
gemini_client = None


class VisibleTextParser(HTMLParser):
	"""Collect visible text while ignoring script and style content."""

	def __init__(self) -> None:
		super().__init__(convert_charrefs=True)
		self.parts: list[str] = []
		self.ignored_depth = 0

	def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
		if tag.lower() in {"script", "style", "noscript"}:
			self.ignored_depth += 1

	def handle_endtag(self, tag: str) -> None:
		if tag.lower() in {"script", "style", "noscript"} and self.ignored_depth:
			self.ignored_depth -= 1

	def handle_data(self, data: str) -> None:
		if not self.ignored_depth and data.strip():
			self.parts.append(data.strip())


def read_document(path: Path) -> str:
	"""Extract text from the supported local document formats."""
	suffix = path.suffix.lower()
	if suffix in {".txt", ".md", ".csv"}:
		return path.read_text(encoding="utf-8-sig", errors="replace")
	if suffix in {".html", ".htm"}:
		parser = VisibleTextParser()
		parser.feed(path.read_text(encoding="utf-8", errors="replace"))
		return "\n".join(parser.parts)
	if suffix == ".pdf":
		try:
			from pypdf import PdfReader
		except ImportError as error:
			raise RuntimeError("Install pypdf with: pip install -r requirements-local.txt") from error
		return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)
	if suffix == ".docx":
		with zipfile.ZipFile(path) as archive:
			document = ET.fromstring(archive.read("word/document.xml"))
		return "\n".join(
			"".join(node.text or "" for node in paragraph.iter() if node.tag.endswith("}t"))
			for paragraph in document.iter()
			if paragraph.tag.endswith("}p")
		)
	return ""


def load_documents(folder: Path) -> list[dict[str, str]]:
	"""Load supported files recursively, recording a relative source name."""
	if not folder.is_dir():
		raise ValueError(f"Document folder does not exist: {folder}")

	documents = []
	for path in sorted(folder.rglob("*")):
		if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS:
			text = read_document(path).strip()
			if text:
				documents.append({"source": str(path.relative_to(folder)), "text": text})
	return documents


def split_documents(documents: list[dict[str, str]]) -> list[dict[str, str]]:
	"""Split loaded text into overlapping character chunks, as in the RAG examples."""
	chunks = []
	for document in documents:
		text = document["text"]
		start = 0
		while start < len(text):
			end = min(start + CHUNK_SIZE, len(text))
			if end < len(text):
				boundary = text.rfind(" ", start, end)
				if boundary > start:
					end = boundary
			content = text[start:end].strip()
			if content:
				chunks.append({"source": document["source"], "text": content})
			if end >= len(text):
				break
			start = max(start + 1, end - CHUNK_OVERLAP)
	return chunks


def get_gemini_client():
	"""Create the Gemini API client after checking its key and SDK are available."""
	global gemini_client
	if gemini_client is not None:
		return gemini_client
	api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
	if not api_key:
		raise RuntimeError(
			"Set GEMINI_API_KEY to a key from https://aistudio.google.com/apikey, then restart the app."
		)
	try:
		from google import genai
	except ImportError as error:
		raise RuntimeError("Install dependencies with: pip install -r requirements-local.txt") from error
	gemini_client = genai.Client(api_key=api_key)
	return gemini_client


def embed_texts(texts: list[str], model: str, is_query: bool = False) -> list[list[float]]:
	"""Create Gemini embeddings in batches with retrieval-specific input formatting."""
	from google.genai import types

	vectors = []
	for offset in range(0, len(texts), 32):
		batch = texts[offset : offset + 32]
		contents = []
		for text in batch:
			formatted_text = (
				f"task: question answering | query: {text}"
				if is_query
				else f"title: none | text: {text}"
			)
			contents.append(types.Content(parts=[types.Part.from_text(text=formatted_text)]))
		try:
			result = get_gemini_client().models.embed_content(model=model, contents=contents)
		except Exception as error:
			raise RuntimeError(f"Gemini embedding request failed: {error}") from error
		vectors.extend(embedding.values or [] for embedding in (result.embeddings or []))
	if len(vectors) != len(texts):
		raise RuntimeError("Gemini returned an unexpected number of document embeddings.")
	return vectors


def generate_answer(prompt: str, model: str) -> str:
	"""Generate a grounded answer using the selected Gemini model."""
	try:
		result = get_gemini_client().models.generate_content(model=model, contents=prompt)
	except Exception as error:
		raise RuntimeError(f"Gemini generation request failed: {error}") from error
	if not result.text:
		raise RuntimeError("Gemini returned an empty response.")
	return result.text


def cosine_similarity(first: list[float], second: list[float]) -> float:
	"""Return cosine similarity for two embedding vectors."""
	dot = sum(left * right for left, right in zip(first, second))
	first_norm = math.sqrt(sum(value * value for value in first))
	second_norm = math.sqrt(sum(value * value for value in second))
	return dot / (first_norm * second_norm) if first_norm and second_norm else 0.0


def token_count(text: str) -> int:
	"""Estimate token count with a simple punctuation-aware tokenizer."""
	return len(TOKEN_PATTERN.findall(text))


PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Gemini RAG Lab</title>
  <style>
	:root { color-scheme: light; --ink: #182b28; --muted: #60716b; --paper: #f5f4ee;
	  --panel: #fffefa; --green: #176b52; --line: #d8dfd7; --accent: #e9a93a; }
	* { box-sizing: border-box; }
	body { margin: 0; background: radial-gradient(ellipse at 90% 0%, #d9e7d9 0, transparent 34%), var(--paper);
	  color: var(--ink); font: 16px/1.5 "Segoe UI", sans-serif; }
	main { width: min(1040px, calc(100% - 36px)); margin: 36px auto 70px; }
	header { border-bottom: 1px solid var(--line); padding: 0 0 24px; margin-bottom: 24px; }
	.eyebrow { color: var(--green); font-size: 12px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }
	h1 { font: 700 40px/1.1 Georgia, serif; margin: 8px 0; }
	h2 { font: 700 23px/1.2 Georgia, serif; margin: 0 0 16px; }
	p { margin: 6px 0; color: var(--muted); }
	.layout { display: grid; grid-template-columns: minmax(260px, .85fr) minmax(0, 1.5fr); gap: 18px; align-items: start; }
	section { background: var(--panel); border: 1px solid var(--line); border-radius: 7px; padding: 22px; }
	label { display: block; font-size: 13px; font-weight: 650; margin: 14px 0 5px; }
	input { width: 100%; min-height: 42px; border: 1px solid #b9c7be; border-radius: 4px; padding: 9px 10px; color: var(--ink); background: white; }
	button { margin-top: 16px; min-height: 42px; border: 0; border-radius: 4px; padding: 9px 14px; background: var(--green); color: white; font-weight: 700; cursor: pointer; }
	button:hover { background: #10533f; }
	.wide { width: 100%; }
	.status { border-left: 4px solid var(--accent); padding: 10px 12px; margin: 0 0 18px; background: #fff6df; color: #61470f; }
	.answer { white-space: pre-wrap; color: var(--ink); }
	.sources { padding-left: 20px; color: var(--muted); overflow-wrap: anywhere; }
	.stats { border-top: 1px solid var(--line); margin-top: 16px; padding-top: 12px; font-size: 13px; color: var(--muted); }
	code { background: #eef1e9; border-radius: 3px; padding: 2px 4px; overflow-wrap: anywhere; }
	.models { margin-top: 18px; font-size: 13px; }
	@media (max-width: 700px) { main { margin-top: 22px; } h1 { font-size: 34px; } .layout { grid-template-columns: 1fr; } }
  </style>
</head>
<body><main>
  <header><div class="eyebrow">Local document retrieval · Gemini API</div><h1>RAG Lab</h1>
	<p>Load a folder, retrieve relevant passages, and ask Gemini.</p></header>
  {% if message %}<div class="status">{{ message }}</div>{% endif %}
  <div class="layout">
	<section><h2>1. Build the index</h2>
	  <form action="/index" method="post">
		<label for="folder">Document folder</label><input id="folder" name="folder" value="{{ folder }}" required>
		<label for="embed_model">Embedding model</label><input id="embed_model" name="embed_model" value="{{ embed_model }}" required>
		<label for="chat_model">Chat model</label><input id="chat_model" name="chat_model" value="{{ chat_model }}" required>
		<button class="wide" type="submit">Load documents and index</button>
	  </form>
	  <div class="models"><strong>Free-tier model suggestions</strong>
		<p>Chat: <code>gemini-3.8-flash</code> (recommended) or <code>gemini-3.5-flash-lite</code> (lighter).</p>
		<p>Embeddings: <code>gemini-embedding-2</code> (recommended) or <code>gemini-embedding-001</code> (text-only).</p>
		<p>Get a key from Google AI Studio and set the <code>GEMINI_API_KEY</code> environment variable.</p>
	  </div>
	  <div class="stats">{% if chunk_count %}Indexed {{ chunk_count }} chunks from {{ source_count }} files.{% else %}No documents indexed yet.{% endif %}</div>
	</section>
	<section><h2>2. Ask your documents</h2>
	  <form action="/ask" method="post">
		<label for="question">Question</label><input id="question" name="question" placeholder="Ask a question grounded in your files" required>
		<button type="submit" {% if not chunk_count %}disabled{% endif %}>Ask</button>
	  </form>
	  {% if answer %}<div class="stats"><strong>Answer</strong><p class="answer">{{ answer }}</p>
		<strong>Retrieved sources</strong><ul class="sources">{% for source in sources %}<li>{{ source }}</li>{% endfor %}</ul></div>{% endif %}
	  <div class="stats">Supported: TXT, Markdown, CSV, HTML, PDF, DOCX. Chunking uses {{ chunk_size }} characters with {{ overlap }} characters of overlap; token counts use a punctuation-aware estimate. Embedding and answer requests send text to Google's API; local retrieval runs in this app.</div>
	</section>
  </div>
</main></body></html>"""


def render_page(
	message: str = "",
	answer: str = "",
	sources: list[str] | None = None,
	folder: str | None = None,
) -> str:
	source_count = len({chunk["source"] for chunk in indexed_chunks})
	return render_template_string(
		PAGE,
		message=message,
		answer=answer,
		sources=sources or [],
		folder=folder or str(DEFAULT_DOCUMENT_DIR),
		chat_model=chat_model,
		embed_model=embed_model,
		chunk_count=len(indexed_chunks),
		source_count=source_count,
		chunk_size=CHUNK_SIZE,
		overlap=CHUNK_OVERLAP,
	)


@app.get("/")
def index() -> str:
	return render_page()


@app.post("/index")
def build_index() -> str:
	global indexed_chunks, indexed_vectors, chat_model, embed_model
	folder_text = request.form.get("folder", "").strip()
	chat_model = request.form.get("chat_model", DEFAULT_CHAT_MODEL).strip()
	embed_model = request.form.get("embed_model", DEFAULT_EMBED_MODEL).strip()
	try:
		documents = load_documents(Path(folder_text).expanduser())
		chunks = split_documents(documents)
		if not chunks:
			raise ValueError("No readable supported documents were found in that folder.")
		vectors = embed_texts([chunk["text"] for chunk in chunks], embed_model)
		indexed_chunks, indexed_vectors = chunks, vectors
		return render_page(
			f"Indexed {len(chunks)} chunks from {len(documents)} documents. "
			f"Example chunk size: {token_count(chunks[0]['text'])} estimated tokens.",
			folder=folder_text,
		)
	except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as error:
		return render_page(str(error), folder=folder_text), 400


@app.post("/ask")
def ask() -> str | tuple[str, int]:
	question = request.form.get("question", "").strip()
	if not question:
		return render_page("Enter a question first."), 400
	if not indexed_chunks:
		return render_page("Index a document folder before asking a question."), 400

	try:
		query_vector = embed_texts([question], embed_model, is_query=True)[0]
		ranked = sorted(
			range(len(indexed_chunks)),
			key=lambda index: cosine_similarity(query_vector, indexed_vectors[index]),
			reverse=True,
		)[:4]
		context = "\n\n".join(
			f"Source: {indexed_chunks[index]['source']}\n{indexed_chunks[index]['text']}"
			for index in ranked
		)
		prompt = (
			"Answer using only the supplied context. If it does not contain the answer, "
			"say you do not know. Cite the source filenames in your answer. Keep the answer concise.\n\n"
			f"Context:\n{context}\n\nQuestion: {question}\nAnswer:"
		)
		answer = generate_answer(prompt, chat_model)
		sources = list(dict.fromkeys(indexed_chunks[index]["source"] for index in ranked))
		return render_page(answer=answer, sources=sources)
	except (IndexError, RuntimeError) as error:
		return render_page(str(error)), 502


if __name__ == "__main__":
	app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
