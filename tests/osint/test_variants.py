import pytest

from osint import variants


@pytest.mark.parametrize("raw,first,middle,last", [
    ("Cagan Efe Calidag", "cagan", ["efe"], "calidag"),
    ("Çağan Efe Çalıdağ", "cagan", ["efe"], "calidag"),   # Turkish folding
    ("Ada Lovelace", "ada", [], "lovelace"),
    ("Calidag, Cagan Efe", "cagan", ["efe"], "calidag"),  # "Last, First" form
    ("Jan van der Berg", "jan", [], "vandberg".replace("vandberg", "vanderberg")),
    ("Müller", "muller", [], ""),
])
def test_split_name(raw, first, middle, last):
    n = variants.split_name(raw)
    assert n["first"] == first
    assert n["middle"] == middle
    assert n["last"] == last


def test_split_name_rejects_junk():
    with pytest.raises(ValueError):
        variants.split_name("   !!!   ")


def test_handles_put_full_names_before_abbreviations():
    """The obvious spellings must come first — callers only sweep the top N."""
    h = variants.handles_from_name("Cagan Efe Calidag")
    assert h[0] == "cagancalidag"
    for real in ("cagancalidag", "caganefecalidag", "caganc", "ccalidag"):
        assert real in h
    # full concatenations outrank initial-abbreviated and truncated forms
    assert h.index("cagancalidag") < h.index("ccalidag")
    assert h.index("caganefecalidag") < h.index("caganc")
    assert h.index("caganefecalidag") < h.index("cagancal")


def test_handles_are_unique_and_capped():
    h = variants.handles_from_name("Ada Lovelace", limit=5)
    assert len(h) == 5
    assert len(set(h)) == 5


def test_handles_with_years():
    h = variants.handles_from_name("Ada Lovelace", include_years=(1815,))
    assert "adalovelace1815" in h


@pytest.mark.parametrize("handle,core,digits", [
    ("xX_realdave1994_Xx", "dave", ["1994"]),
    ("thecagan", "cagan", []),
    ("dave_dev", "dave", []),
    ("plainname", "plainname", []),
])
def test_strip_affixes(handle, core, digits):
    out = variants.strip_affixes(handle)
    assert out["core"] == core
    assert out["digits"] == digits


def test_strip_affixes_never_eats_the_whole_handle():
    assert variants.strip_affixes("real")["core"] == "real"
    assert variants.strip_affixes("xx")["core"] == "xx"


def test_email_candidates_ordering_and_domain_cleanup():
    e = variants.email_candidates("Ada Lovelace", "https://Example.com/contact")
    assert e[0] == "ada.lovelace@example.com"
    assert "alovelace@example.com" in e
    assert all(x.endswith("@example.com") for x in e)


def test_email_candidates_rejects_bad_domain():
    with pytest.raises(ValueError):
        variants.email_candidates("Ada Lovelace", "notadomain")


def test_run_requires_a_seed():
    with pytest.raises(ValueError):
        variants.run()


def test_run_shape():
    res = variants.run(name="Ada Lovelace", email_domain="example.com",
                       handle="xX_ada_Xx")
    assert res["handles"] and res["emails"]
    assert res["normalized"]["core"] == "ada"
    assert res["next_steps"]


def test_main_no_args_returns_2():
    assert variants.main([]) == 2
