"""Thin OpenAI wrapper for the chatbot page -- self-contained under
dashboard/ for the same sys.path reason as _rag_retriever.py. Raises
NoApiKeyError so the page can show a friendly message instead of crashing
when OPENAI_API_KEY isn't set."""
import os

from openai import OpenAI

MODEL_NAME = "gpt-4o-mini"  # ponytail: cheap/fast default, swap here if you want a different model


class NoApiKeyError(Exception):
    pass


def ask(system_prompt: str, user_message: str) -> str:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise NoApiKeyError("OPENAI_API_KEY is not set")
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
    )
    return response.choices[0].message.content
