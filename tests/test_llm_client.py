"""Offline tests for the Claude backend: request shape, parsing, caching, refusal handling (no network, no key)."""
import json
from types import SimpleNamespace

import pytest

anthropic = pytest.importorskip("anthropic")
from src import llm_investigator as li


class FakeMessages:
    def __init__(self, stop="end_turn"):
        self.stop, self.calls = stop, []

    def create(self, **kw):
        self.calls.append(kw)
        return SimpleNamespace(stop_reason=self.stop, stop_details=None, model=kw["model"], _request_id="req_x",
                               usage=SimpleNamespace(input_tokens=100, output_tokens=20),
                               content=[SimpleNamespace(type="text", text=json.dumps({"hypothesis": "h", "attack_likelihood": 0.7, "choice": 1}))])


def _client(tmp_path, monkeypatch, stop="end_turn"):
    monkeypatch.setattr(li, "CACHE", tmp_path)
    c = li.AnthropicClient.__new__(li.AnthropicClient)
    c.model, c.effort, c.calls, c.cache_hits, c.usage, c.last_model = "claude-opus-5-5", "low", 0, 0, {"input": 0, "output": 0}, None
    fm = FakeMessages(stop)
    c.client = SimpleNamespace(beta=SimpleNamespace(messages=fm))
    return c, fm


def test_request_shape_and_cache(tmp_path, monkeypatch):
    c, fm = _client(tmp_path, monkeypatch)
    out = json.loads(c.chat("sys", "user"))
    assert out["choice"] == 1 and c.calls == 1
    kw = fm.calls[0]
    assert kw["model"] == "claude-opus-5-5" and "temperature" not in kw and "thinking" not in kw
    assert kw["output_config"]["format"]["type"] == "json_schema" and kw["output_config"]["effort"] == "low"
    c.chat("sys", "user")
    assert c.calls == 1 and c.cache_hits == 1 and len(fm.calls) == 1


def test_refusal_raises_and_is_not_cached(tmp_path, monkeypatch):
    c, _ = _client(tmp_path, monkeypatch, stop="refusal")
    with pytest.raises(RuntimeError):
        c.chat("sys", "user")
    assert not list(tmp_path.glob("*.json"))


def test_make_client_routing(monkeypatch):
    assert isinstance(li.make_client("llm"), li.LLMClient)
