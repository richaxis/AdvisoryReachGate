"""
Direct tests: drive the contract's public methods against a fake runtime
(web, model and clock are mocked). They check the state machine, fences,
deadlines and access control. They do not simulate validator agreement.
"""
import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fake_genlayer import load_contract  # noqa: E402

gl, C = load_contract()

OWNER, W2, W3, STRANGER = "aa", "bb", "cc", "dd"
ADV_HOST, MAN_HOST = "api.osv.dev", "raw.githubusercontent.com"
T0 = 1_800_000_000


def sha(b):
    return hashlib.sha256(b).hexdigest()


def osv(package="requests", severity="HIGH", fixed="2.31.0"):
    return json.dumps({
        "affected": [{"package": {"name": package, "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.3.0"}, {"fixed": fixed}]}]}],
        "database_specific": {"severity": severity},
    }).encode()


class Base(unittest.TestCase):
    def setUp(self):
        gl.set_time(T0)
        gl.web.pages.clear()
        gl.llm_calls = 0
        gl.as_user(OWNER)
        self.c = C.AdvisoryReachGate()
        self.c.create_pool("pool-one", "PyPI", ADV_HOST, MAN_HOST)
        self.c.set_worker("pool-one", "0x" + W2 * 20, True)
        self.n = 0

    def add(self, pin="2.27.0", severity="HIGH", package="requests", review=7200, who=OWNER, adv=None):
        self.n += 1
        adv = adv or osv(package=package, severity=severity)
        man = f"{package}=={pin}\n# {self.n}\n".encode()
        au = f"https://{ADV_HOST}/v1/vulns/GHSA-{self.n}"
        mu = f"https://{MAN_HOST}/o/r/{'a' * 40}/requirements{self.n}.txt"
        gl.web.pages[au] = (200, adv)
        gl.web.pages[mu] = (200, man)
        gl.as_user(who)
        return self.c.enqueue_check("pool-one", au, sha(adv), mu, sha(man), package, gl.now + review)

    def job(self, jid):
        return self.c.get_job("pool-one", jid)


class AdmissionTests(Base):
    def test_affected_is_queued_with_priority_from_evidence(self):
        j = self.job(self.add(severity="CRITICAL"))
        self.assertEqual((j["state"], j["priority"], j["verdict"]), ("QUEUED", "URGENT", "AFFECTED"))
        self.assertEqual(j["report"]["method"], "osv")

    def test_not_affected_is_cleared_and_never_dispatched(self):
        jid = self.add(pin="2.31.0")
        self.assertEqual(self.job(jid)["state"], "CLEARED")
        self.assertEqual(self.c.lease_next("pool-one", 60), "")

    def test_unknown_is_blocked_and_never_dispatched(self):
        jid = self.add(pin="2.0rc1")
        self.assertEqual(self.job(jid)["state"], "BLOCKED")
        self.assertEqual(self.c.lease_next("pool-one", 60), "")

    def test_wrong_hash_is_blocked_not_trusted(self):
        adv, man = osv(), b"requests==2.27.0\n"
        au = f"https://{ADV_HOST}/v1/vulns/GHSA-h"
        mu = f"https://{MAN_HOST}/o/r/{'b' * 40}/r.txt"
        gl.web.pages[au] = (200, adv)
        gl.web.pages[mu] = (200, man)
        jid = self.c.enqueue_check("pool-one", au, "0" * 64, mu, sha(man), "requests", gl.now + 600)
        j = self.job(jid)
        self.assertEqual(j["state"], "BLOCKED")
        self.assertEqual(j["report"]["reason"], "advisory_hash_mismatch")

    def test_http_404_is_blocked(self):
        adv, man = osv(), b"requests==2.27.0\n"
        au = f"https://{ADV_HOST}/v1/vulns/missing"
        mu = f"https://{MAN_HOST}/o/r/{'c' * 40}/r.txt"
        gl.web.pages[mu] = (200, man)
        jid = self.c.enqueue_check("pool-one", au, sha(adv), mu, sha(man), "requests", gl.now + 600)
        self.assertEqual(self.job(jid)["report"]["reason"], "advisory_http_404")

    def test_no_caller_supplied_priority_or_verdict_exists(self):
        import inspect
        params = inspect.signature(C.AdvisoryReachGate.enqueue_check).parameters
        for name in params:
            self.assertNotIn(name, ("priority", "verdict", "severity", "affected"))

    def test_same_comparison_cannot_be_resampled(self):
        adv, man = osv(), b"requests==2.27.0\n"
        au = f"https://{ADV_HOST}/v1/vulns/GHSA-dup"
        mu = f"https://{MAN_HOST}/o/r/{'d' * 40}/r.txt"
        gl.web.pages[au] = (200, adv)
        gl.web.pages[mu] = (200, man)
        args = ("pool-one", au, sha(adv), mu, sha(man), "requests", gl.now + 600)
        self.c.enqueue_check(*args)
        with self.assertRaises(gl.vm.UserError):
            self.c.enqueue_check(*args)

    def test_host_allowlist_enforced(self):
        with self.assertRaises(gl.vm.UserError):
            self.c.enqueue_check("pool-one", "https://evil.example/x", "0" * 64,
                                 f"https://{MAN_HOST}/x", "0" * 64, "requests", gl.now + 600)

    def test_review_deadline_bounds(self):
        for bad in (gl.now + 5, gl.now + 8 * 86400, gl.now - 10):
            with self.assertRaises(gl.vm.UserError):
                self.c.enqueue_check("pool-one", f"https://{ADV_HOST}/x", "0" * 64,
                                     f"https://{MAN_HOST}/x", "0" * 64, "requests", bad)

    def test_non_member_cannot_enqueue(self):
        with self.assertRaises(gl.vm.UserError):
            self.add(who=STRANGER)

    def test_pool_cap(self):
        for _ in range(C.MAX_POOL_JOBS):
            self.add(pin="2.31.0")
        with self.assertRaises(gl.vm.UserError):
            self.add(pin="2.31.0")

    def test_bad_inputs_rejected(self):
        with self.assertRaises(gl.vm.UserError):
            self.c.create_pool("Bad Pool!", "PyPI", ADV_HOST, MAN_HOST)
        with self.assertRaises(gl.vm.UserError):
            self.c.create_pool("pool-two", "cargo", ADV_HOST, MAN_HOST)
        with self.assertRaises(gl.vm.UserError):
            self.c.create_pool("pool-one", "PyPI", ADV_HOST, MAN_HOST)


class QueueTests(Base):
    def test_urgent_before_normal_then_fifo(self):
        n1 = self.add(severity="LOW")
        gl.set_time(T0 + 1)
        n2 = self.add(severity="LOW")
        gl.set_time(T0 + 2)
        u1 = self.add(severity="CRITICAL")
        gl.set_time(T0 + 3)
        order = []
        for who in (OWNER, W2):
            gl.as_user(who)
            order.append(int(self.c.lease_next("pool-one", 300)))
        self.assertEqual(order[0], u1)
        self.assertEqual(order[1], n1)
        self.assertNotIn(n2, order)

    def test_aging_lets_old_normal_beat_new_urgent(self):
        old = self.add(severity="LOW")
        gl.set_time(T0 + C.AGING_SECONDS + 1)
        self.add(severity="CRITICAL")
        gl.as_user(OWNER)
        self.assertEqual(int(self.c.lease_next("pool-one", 300)), old)

    def test_one_live_lease_per_worker(self):
        self.add()
        self.add()
        gl.as_user(OWNER)
        self.c.lease_next("pool-one", 300)
        with self.assertRaises(gl.vm.UserError):
            self.c.lease_next("pool-one", 300)

    def test_lease_bounds_and_membership(self):
        self.add()
        with self.assertRaises(gl.vm.UserError):
            self.c.lease_next("pool-one", 1)
        with self.assertRaises(gl.vm.UserError):
            self.c.lease_next("pool-one", 3601)
        gl.as_user(STRANGER)
        with self.assertRaises(gl.vm.UserError):
            self.c.lease_next("pool-one", 60)

    def test_lease_capped_by_review_deadline(self):
        jid = self.add(review=100)
        gl.as_user(OWNER)
        self.c.lease_next("pool-one", 3600)
        self.assertEqual(self.job(jid)["lease_expires"], gl.now + 100)

    def test_ack_requires_holder_and_exact_fence(self):
        jid = self.add()
        gl.as_user(OWNER)
        self.c.lease_next("pool-one", 300)
        gl.as_user(W2)
        with self.assertRaises(gl.vm.UserError):
            self.c.acknowledge("pool-one", jid, 1)
        gl.as_user(OWNER)
        with self.assertRaises(gl.vm.UserError):
            self.c.acknowledge("pool-one", jid, 2)
        self.c.acknowledge("pool-one", jid, 1)
        self.assertEqual(self.job(jid)["state"], "ACKNOWLEDGED")
        with self.assertRaises(gl.vm.UserError):
            self.c.acknowledge("pool-one", jid, 1)

    def test_stale_worker_cannot_close_newer_lease(self):
        jid = self.add()
        gl.as_user(OWNER)
        self.c.lease_next("pool-one", 10)
        gl.set_time(T0 + 11)
        gl.as_user(W2)
        self.assertEqual(int(self.c.lease_next("pool-one", 300)), jid)
        self.assertEqual(self.job(jid)["fence"], 2)
        gl.as_user(OWNER)
        with self.assertRaises(gl.vm.UserError):
            self.c.acknowledge("pool-one", jid, 1)
        gl.as_user(W2)
        self.c.acknowledge("pool-one", jid, 2)

    def test_expired_lease_cannot_be_acknowledged(self):
        jid = self.add()
        gl.as_user(OWNER)
        self.c.lease_next("pool-one", 10)
        gl.set_time(T0 + 10)
        with self.assertRaises(gl.vm.UserError):
            self.c.acknowledge("pool-one", jid, 1)

    def test_release_requeues_and_renews_fifo_position(self):
        a = self.add(severity="LOW")
        gl.set_time(T0 + 1)
        b = self.add(severity="LOW")
        gl.as_user(OWNER)
        self.assertEqual(int(self.c.lease_next("pool-one", 300)), a)
        gl.set_time(T0 + 2)
        self.c.release("pool-one", a, 1)
        self.assertEqual(self.job(a)["state"], "QUEUED")
        self.assertEqual(int(self.c.lease_next("pool-one", 300)), b)

    def test_anyone_can_recover_expired_lease(self):
        jid = self.add()
        gl.as_user(OWNER)
        self.c.lease_next("pool-one", 10)
        gl.as_user(STRANGER)
        with self.assertRaises(gl.vm.UserError):
            self.c.recover("pool-one", jid)
        gl.set_time(T0 + 10)
        self.c.recover("pool-one", jid)
        self.assertEqual(self.job(jid)["state"], "QUEUED")
        gl.as_user(OWNER)
        self.assertEqual(int(self.c.lease_next("pool-one", 60)), jid)

    def test_deadline_beats_requeue(self):
        jid = self.add(review=60)
        gl.as_user(OWNER)
        self.c.lease_next("pool-one", 30)
        gl.set_time(T0 + 60)
        gl.as_user(STRANGER)
        self.c.recover("pool-one", jid)
        self.assertEqual(self.job(jid)["state"], "EXPIRED")

    def test_empty_dispatch_returns_blank_and_commits_expiry(self):
        jid = self.add(review=60)
        gl.set_time(T0 + 61)
        gl.as_user(OWNER)
        self.assertEqual(self.c.lease_next("pool-one", 60), "")
        self.assertEqual(self.job(jid)["state"], "EXPIRED")

    def test_owner_cannot_revoke_live_assignment(self):
        jid = self.add()
        gl.as_user(W2)
        self.c.lease_next("pool-one", 300)
        gl.as_user(OWNER)
        self.c.set_worker("pool-one", "0x" + W2 * 20, False)
        self.assertEqual(self.job(jid)["state"], "LEASED")
        gl.as_user(W2)
        self.c.acknowledge("pool-one", jid, 1)

    def test_only_owner_manages_members(self):
        gl.as_user(W2)
        with self.assertRaises(gl.vm.UserError):
            self.c.set_worker("pool-one", "0x" + W3 * 20, True)

    def test_jobs_are_bound_to_their_pool(self):
        jid = self.add()
        gl.as_user(OWNER)
        self.c.create_pool("pool-two", "PyPI", ADV_HOST, MAN_HOST)
        with self.assertRaises(gl.vm.UserError):
            self.c.get_job("pool-two", jid)
        with self.assertRaises(gl.vm.UserError):
            self.c.acknowledge("pool-two", jid, 1)

    def test_event_log_is_append_only_and_readable(self):
        self.add()
        n = self.c.event_count()
        self.assertGreaterEqual(n, 3)
        kinds = [self.c.get_event(i)["kind"] for i in range(n)]
        self.assertEqual(kinds[0], "POOL_CREATED")
        self.assertIn("ADMITTED_QUEUED", kinds)


class FallbackIntegrationTests(Base):
    def test_prose_advisory_goes_through_model_and_is_grounded(self):
        text = b"The requests package leaks headers. Versions before 2.31.0 are affected by this bug.\n"
        gl.llm_answer = json.dumps({"introduced": None, "fixed": "2.31.0", "last_affected": None,
                                    "quote": "Versions before 2.31.0 are affected by this bug."})
        jid = self.add(adv=text)
        j = self.job(jid)
        self.assertEqual((j["state"], j["report"]["method"]), ("QUEUED", "llm"))
        self.assertEqual(gl.llm_calls, 1)

    def test_ungrounded_model_answer_blocks(self):
        text = b"The requests package leaks headers. Versions before 2.31.0 are affected by this bug.\n"
        gl.llm_answer = json.dumps({"introduced": None, "fixed": "9.9.9", "last_affected": None,
                                    "quote": "Versions before 9.9.9 are affected by this bug."})
        jid = self.add(adv=text)
        self.assertEqual(self.job(jid)["state"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
