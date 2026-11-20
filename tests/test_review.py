"""Detection v2: record growth only on rare behaviour, and the daily review queue."""

from authority.actions import Action
from authority.features import DAY
from authority.novelty import NoveltyScorer, ReviewQueue

T0 = 1_700_000_000.0


def _org(nov: NoveltyScorer, days: int = 8) -> None:
    """20 people read the CRM every day; only 'ops' ever exports files."""
    for d in range(days):
        ts = T0 + d * DAY + 10 * 3600
        for i in range(20):
            for _ in range(3):
                nov.observe(Action(f"human:u{i}", "data.read", "crm/accounts", count=10, ts=ts))
        nov.observe(Action("human:ops", "data.export", "files/reports", count=2, ts=ts))
        for _ in range(25):
            nov.observe(Action("human:ops", "data.read", "crm/accounts", count=1, ts=ts))


def test_common_volume_growth_adds_nothing():
    nov = NoveltyScorer()
    _org(nov)
    ts = T0 + 9 * DAY + 10 * 3600
    s, _ = nov.raw(Action("human:u1", "data.read", "crm/accounts", count=500, ts=ts))
    assert s == 0.0  # everybody reads the CRM: a big day is not news


def test_rare_volume_growth_still_counts():
    nov = NoveltyScorer()
    _org(nov)
    ts = T0 + 9 * DAY + 10 * 3600
    s, why = nov.raw(Action("human:ops", "data.export", "files/reports", count=200, ts=ts))
    assert s > 0 and any("own previous daily record" in w for w in why)


def test_review_queue_keeps_the_top_few_per_day():
    q = ReviewQueue(per_day=2)
    for i, sc in enumerate([0.1, 0.9, 0.5, 0.0]):
        q.note(f"human:u{i}", T0, sc, [f"r{i}"])
    q.note("human:u0", T0 + 60, 0.7, ["later, stronger"])  # keeps each person's worst moment
    top = q.top(T0)
    assert [t["identity"] for t in top] == ["human:u1", "human:u0"]
    assert top[1]["why"] == ["later, stronger"]
    assert q.top(T0 + DAY) == []  # a new day starts empty
