"""
Minimal stand-in for the GenLayer SDK so the contract can be imported and
exercised without GenVM. It does NOT simulate validator agreement: strict_eq
just runs the leader function once. Real consensus evidence lives in
LIVE_PROOFS.md (Studio Next receipts).
"""
import sys
import types
import typing
from datetime import datetime, timezone
from pathlib import Path
from importlib import util


class UserError(Exception):
    pass


class TreeMap(dict):
    pass


class Address:
    def __init__(self, value):
        v = str(value).lower()
        if not (v.startswith("0x") and len(v) == 42 and int(v[2:], 16) >= 0):
            raise ValueError("bad address")
        self.as_hex = v


class Contract:
    def __new__(cls, *a, **k):
        obj = super().__new__(cls)
        for name, ann in getattr(cls, "__annotations__", {}).items():
            if typing.get_origin(ann) is TreeMap:
                setattr(obj, name, TreeMap())
            elif ann is int:
                setattr(obj, name, 0)
        return obj


class _Web:
    def __init__(self):
        self.pages = {}

    def get(self, url):
        status, body = self.pages.get(url, (404, b""))
        return types.SimpleNamespace(status=status, body=body)


class FakeGL(types.ModuleType):
    def __init__(self):
        super().__init__("genlayer")
        self.contract = types.SimpleNamespace(Contract=Contract)
        self.public = types.SimpleNamespace(view=lambda f: f, write=lambda f: f)
        self.storage = types.SimpleNamespace(TreeMap=TreeMap)
        self.vm = types.SimpleNamespace(UserError=UserError)
        self.web = _Web()
        self.llm_answer = "{}"
        self.llm_calls = 0
        self.nondet = types.SimpleNamespace(web=self.web, exec_prompt=self._prompt)
        self.eq_principle = types.SimpleNamespace(strict_eq=lambda fn: fn())
        self.message = types.SimpleNamespace(
            sender_address=types.SimpleNamespace(as_hex="0x" + "aa" * 20)
        )
        self.message_raw = {}
        self.now = 0
        self.set_time(1_800_000_000)

    def _prompt(self, prompt):
        self.llm_calls += 1
        return self.llm_answer

    def set_time(self, epoch):
        self.now = epoch
        iso = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
        self.message_raw = {"datetime": iso}

    def as_user(self, byte_hex):
        self.message.sender_address = types.SimpleNamespace(as_hex="0x" + byte_hex * 20)


def load_contract():
    gl = FakeGL()
    types_mod = types.ModuleType("genlayer.types")
    types_mod.u256 = int
    types_mod.Address = Address
    sys.modules["genlayer"] = gl
    sys.modules["genlayer.types"] = types_mod
    path = Path(__file__).resolve().parents[1] / "contracts" / "AdvisoryReachGate.py"
    spec = util.spec_from_file_location("advisory_reach_gate", path)
    mod = util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return gl, mod
