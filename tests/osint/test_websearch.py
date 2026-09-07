import pytest

from osint import fetch, websearch

DDG_HTML = """
<div><a class="result__a" href="https://github.com/ada">Ada on GitHub</a>
<a class="result__snippet" href="#">Profile of Ada</a></div>
<div><a class="result__a" href="https://example.com/ada">Ada page</a>
<a class="result__snippet" href="#">Personal site</a></div>
"""

SEARXNG_HTML = """
<article class="result result-default category-general">
<a href="https://github.com/ada" class="url_header"><div>github.com</div></a>
<h3><a href="https://github.com/ada">Ada (ada) - GitHub</a></h3>
<p class="content">Ada's profile on GitHub.</p>
</article>
<article class="result result-default">
<h3><a href="https://linkedin.com/in/ada">Ada - Engineer | LinkedIn</a></h3>
<p class="content">Experience: Acme</p>
</article>
"""


def test_parse_ddg_html():
    out = websearch._parse_ddg_html(DDG_HTML)
    assert [r["url"] for r in out] == ["https://github.com/ada", "https://example.com/ada"]
    assert out[0]["snippet"] == "Profile of Ada"


def test_parse_searxng():
    out = websearch._parse_searxng(SEARXNG_HTML)
    assert [r["url"] for r in out] == ["https://github.com/ada", "https://linkedin.com/in/ada"]
    assert out[0]["title"] == "Ada (ada) - GitHub"
    assert out[0]["snippet"] == "Ada's profile on GitHub."


@pytest.mark.parametrize("wrapped,expected", [
    ("https://duckduckgo.com/l/?uddg=https%3A%2F%2Fgithub.com%2Fada",
     "https://github.com/ada"),
    ("https://www.bing.com/ck/a?!&&p=1&u=a1aHR0cHM6Ly9naXRodWIuY29tL2FkYQ",
     "https://github.com/ada"),
    ("https://r.search.yahoo.com/RU=https%3A%2F%2Fgithub.com%2Fada/RK=2",
     "https://github.com/ada"),
    ("//example.com/x", "https://example.com/x"),
    ("https://plain.example/x", "https://plain.example/x"),
])
def test_unwrap_redirects(wrapped, expected):
    assert websearch._unwrap(wrapped) == expected


def test_clean_html_strips_breadcrumb_prefix():
    raw = "Githubhttps://github.com › torvalds torvalds (Linus Torvalds) · GitHub"
    assert websearch._clean_html(raw) == "torvalds (Linus Torvalds) · GitHub"


def test_clean_html_keeps_plain_titles():
    assert websearch._clean_html("A Normal Title") == "A Normal Title"


def test_generic_parser_drops_engine_navigation():
    page = ('<a href="https://www.bing.com/settings">Settings</a>'
            '<a href="https://github.com/ada">Ada GitHub</a>'
            '<a href="/local">local</a>')
    out = websearch._parse_generic(page, "bing.com")
    assert [r["url"] for r in out] == ["https://github.com/ada"]


def test_search_merges_and_ranks_by_agreement(monkeypatch):
    def two_engines(sources, **kw):
        return ({
            "e1": [{"url": "https://a.test", "title": "A", "snippet": "", "rank": 1},
                   {"url": "https://b.test", "title": "B", "snippet": "", "rank": 2}],
            "e2": [{"url": "https://b.test/", "title": "B longer", "snippet": "s",
                    "rank": 1}],
        }, {"e3": "no results"})

    monkeypatch.setattr(websearch.fetch, "gather", two_engines)
    res = websearch.search("q")
    assert res["results"][0]["url"].startswith("https://b.test")
    assert res["results"][0]["agreement"] == 2
    assert res["results"][0]["title"] == "B longer"
    assert res["engines_down"] == {"e3": "no results"}


def test_person_dorks_cover_every_social_platform():
    dorks = websearch.person_dorks("Ada Lovelace", handle="ada")
    joined = " ".join(dorks)
    for _, site in websearch.SOCIAL_SITES:
        assert site.split(" OR ")[0] in joined
    assert '"Ada Lovelace"' in dorks[0]


def test_person_dorks_include_extra_terms():
    d = websearch.person_dorks("Ada Lovelace", extra='"Acme"')
    assert any('"Acme"' in q for q in d)


def test_keyed_engines_skipped_without_env(monkeypatch):
    for var in websearch.KEYED_ENGINES.values():
        monkeypatch.delenv(var, raising=False)
    assert websearch._brave_api("q", 10) == []
    assert websearch._google_cse("q", 10) == []
    assert websearch._serper("q", 10) == []


def test_searxng_uses_configured_instance_first(monkeypatch):
    monkeypatch.setenv("SEARX_URL", "http://localhost:8080")
    seen = []

    def fake_get_json(url, **kw):
        seen.append(url)
        return {"results": [{"url": "https://a.test", "title": "A", "content": "c"}]}, None

    monkeypatch.setattr(websearch.fetch, "get_json", fake_get_json)
    out = websearch._searxng("q", 10)
    assert seen[0].startswith("http://localhost:8080/search")
    assert out[0]["url"] == "https://a.test"
    assert out[0]["engine"] == "searxng"


def test_searxng_falls_back_to_html(monkeypatch):
    monkeypatch.setenv("SEARX_URL", "http://localhost:8080")
    monkeypatch.setattr(websearch.fetch, "get_json", lambda *a, **k: (None, None))
    monkeypatch.setattr(websearch.fetch, "get",
                        lambda *a, **k: fetch.Response("u", "u", 200,
                                                       SEARXNG_HTML.encode(), None, 0.0))
    out = websearch._searxng("q", 10)
    assert len(out) == 2 and out[0]["engine"] == "searxng"


def test_run_requires_input():
    with pytest.raises(ValueError):
        websearch.run()


def test_main_no_args_returns_2():
    assert websearch.main([]) == 2


def test_main_rejects_unknown_engine():
    assert websearch.main(["q", "--engines", "nope"]) == 1
