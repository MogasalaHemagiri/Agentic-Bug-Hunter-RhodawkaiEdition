"""NVIDIA NIM provider wiring: chat dispatch, defaults, and key redaction.

Adds NVIDIA NIM alongside every existing provider without breaking any of
them (live-run request):

  - nvidia registered in PROVIDER_PRIORITY / DEFAULT_MODELS / PROVIDER_KEY_ENV
  - aliases nim / nvidia-nim / nvidia_nim normalize to "nvidia"
  - chat() routes nvidia through the shared OpenAI-compatible /chat/completions
    path, with NVIDIA_NIM_BASE_URL overriding the hosted default endpoint
  - nvapi-... keys are redacted by memory/redaction.py before durable
    persistence
"""

import importlib
import os
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

from memory.redaction import redact_obj, redact_text  # noqa: E402


@pytest.fixture
def brain_module(monkeypatch):
    for env in ("BRAIN_PROVIDER", "BRAIN_MODEL", "NVIDIA_API_KEY",
                "NVIDIA_NIM_BASE_URL"):
        monkeypatch.delenv(env, raising=False)
    import brain
    importlib.reload(brain)
    return brain


def _nim_client(brain_module, monkeypatch, base_url=None):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    if base_url:
        monkeypatch.setenv("NVIDIA_NIM_BASE_URL", base_url)
    else:
        monkeypatch.delenv("NVIDIA_NIM_BASE_URL", raising=False)
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    client._http = None
    client.description = ""
    client.provider = "nvidia"
    client.model = None
    return client


def test_nvidia_uses_openai_compat_chat_path(brain_module, monkeypatch):
    """chat() must route nvidia through the shared /chat/completions path."""
    client = _nim_client(brain_module, monkeypatch)
    brain_module.LLMClient._init_provider(client, "nvidia")
    assert client.available is True

    calls = []

    def _fake_chat(model, system, user, max_tokens, temperature):
        calls.append({"model": model, "system": system, "user": user})
        return "nim-reply"

    monkeypatch.setattr(client, "_chat_openai_compat", _fake_chat)
    reply = client.chat(None, "system", "user")

    assert reply == "nim-reply"
    assert len(calls) == 1


def test_nvidia_provider_registry_entries(brain_module):
    dm = brain_module.LLMClient.DEFAULT_MODELS
    assert dm["nvidia"] == "meta/llama-3.3-70b-instruct"
    assert brain_module.LLMClient.PROVIDER_KEY_ENV["nvidia"] == "NVIDIA_API_KEY"
    assert "nvidia" in brain_module.LLMClient.PROVIDER_PRIORITY


def test_nim_aliases_normalize(brain_module, monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    for alias in ("nim", "nvidia-nim", "nvidia_nim"):
        client = brain_module.LLMClient(alias)
        assert client.provider == "nvidia"
        assert client.available is True
        assert "nvidia" in client.description.lower()


NVAPI_KEY = "nvapi-nV1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2"


def test_nvapi_key_redacted_in_text():
    out = redact_text(f"config error at {NVAPI_KEY} — retry")
    assert "nvapi-" not in out
    assert NVAPI_KEY not in out
    assert "[REDACTED:nvidia_key]" in out


def test_nvapi_key_redacted_in_obj_and_idempotent():
    obj = {"note": f"key={NVAPI_KEY}", "nested": [f"Bearer {NVAPI_KEY}"]}
    once = redact_obj(obj)
    assert NVAPI_KEY not in str(once)
    twice = redact_obj(once)
    assert twice == once  # deterministic + idempotent


def test_engine_wires_nvidia_setup_and_providers():
    """engine.py exposes NVIDIA NIM in setup (key + base URL + choices) and
    the providers table, keeping every existing provider untouched."""
    src = open(os.path.join(ROOT, "bughunter", "engine.py"),
               encoding="utf-8").read()
    assert '"nvidia":     "NVIDIA_API_KEY"' in src          # setup env_map
    assert '"nvidia":       "NVIDIA_API_KEY"' in src        # providers table
    assert "NVIDIA_NIM_BASE_URL" in src                     # base URL override
    assert "NVIDIA NIM" in src                              # menu label
    assert '"nvidia", "nim", "nvidia-nim"' in src           # argparse choices
    assert "https://integrate.api.nvidia.com/v1" in src     # default shown
