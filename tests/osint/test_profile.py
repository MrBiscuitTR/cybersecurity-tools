import pytest

from osint import profile

JSONLD_PAGE = """
<html><head>
<title>Ada Lovelace - Analytical Engines | Example</title>
<meta property="og:title" content="Ada Lovelace - Mathematician">
<meta property="og:description" content="Countess and programmer">
<meta property="profile:first_name" content="Ada">
<meta property="profile:last_name" content="Lovelace">
<script type="application/ld+json">
{"@context":"http://schema.org","@graph":[
 {"@type":"Article","headline":"unrelated"},
 {"@type":"Person","name":"Ada Lovelace","birthDate":"1815-12-10",
  "disambiguatingDescription":"First programmer",
  "address":{"@type":"PostalAddress","addressLocality":"London","addressCountry":"GB"},
  "jobTitle":["Mathematician","Writer"],
  "worksFor":[{"@type":"Organization","name":"Analytical Engines",
               "url":"https://example.com/ae",
               "member":{"@type":"OrganizationRole","startDate":1843}}],
  "alumniOf":[{"@type":"EducationalOrganization","name":"Home Tutoring",
               "member":{"@type":"OrganizationRole","startDate":1825,"endDate":1835}}],
  "sameAs":["https://github.com/adalovelace"]}]}
</script></head>
<body>
<a rel="me" href="https://mastodon.social/@ada">fedi</a>
<a href="https://twitter.com/ada_l">twitter</a>
<a href="https://github.com/features/copilot">a product page</a>
<a href="/about">local nav</a>
<p>Contact: ada [at] lovelace [dot] dev or ada.l@lovelace.dev</p>
<p>Born 10 December 1815 in London.</p>
</body></html>
"""


@pytest.fixture()
def extracted():
    return profile.extract(JSONLD_PAGE, base_url="https://example.com/ada")


def test_identity_from_jsonld(extracted):
    i = extracted["identity"]
    assert i["name"] == "Ada Lovelace"
    assert i["locality"] == "London"
    assert i["country"] == "GB"
    assert i["birth_date"] == "1815-12-10"
    assert i["job_titles"] == ["Mathematician", "Writer"]


def test_experience_and_education(extracted):
    i = extracted["identity"]
    assert i["works_for"][0]["name"] == "Analytical Engines"
    assert i["works_for"][0]["start"] == "1843"
    assert i["alumni_of"][0]["end"] == "1835"


def test_rel_me_and_sameas_are_self_declared(extracted):
    urls = {l["url"] for l in extracted["rel_me"]}
    assert "https://mastodon.social/@ada" in urls
    assert "https://github.com/adalovelace" in urls   # from sameAs


def test_ordinary_links_are_separate(extracted):
    platforms = {l["platform"] for l in extracted["links"]}
    assert "x/twitter" in platforms


def test_site_navigation_is_not_an_account(extracted):
    """github.com/features/copilot is a product page, not a person."""
    all_urls = {l["url"] for l in extracted["links"] + extracted["rel_me"]}
    assert "https://github.com/features/copilot" not in all_urls


def test_same_host_links_are_dropped(extracted):
    assert all("example.com/about" not in l["url"]
               for l in extracted["links"] + extracted["rel_me"])


def test_emails_including_obfuscated(extracted):
    assert "ada.l@lovelace.dev" in extracted["emails"]
    assert "ada@lovelace.dev" in extracted["emails"]


def test_no_email_false_positives_from_the_word_at():
    """'at' inside a word must not create an address (notific-at-ions)."""
    html = "<p>We send notifications.Learn more about organizations.If you like.</p>"
    assert profile.extract(html)["emails"] == []


def test_implausible_tlds_rejected():
    html = "<p>see datasette.acme.net. Disclosures follow. real@acme.dev</p>"
    emails = profile.extract(html)["emails"]
    assert "real@acme.dev" in emails
    assert not any(e.endswith(".disclosures") for e in emails)


def test_birth_hints(extracted):
    assert any("1815" in b for b in extracted["birth_hints"])


@pytest.mark.parametrize("url,platform,handle", [
    ("https://github.com/torvalds", "github", "torvalds"),
    ("https://www.linkedin.com/in/williamhgates", "linkedin", "williamhgates"),
    ("https://t.me/durov", "telegram", "durov"),
    ("https://lichess.org/@/chess-network", "lichess", "chess-network"),
])
def test_classify_link(url, platform, handle):
    info = profile.classify_link(url)
    assert info and info["platform"] == platform and info["handle"] == handle


@pytest.mark.parametrize("url", [
    "https://github.com/features/actions",
    "https://github.com/about",
    "https://example.com/random",
    "not-a-url",
])
def test_classify_link_rejects_non_profiles(url):
    assert profile.classify_link(url) is None


def test_run_rejects_bad_url():
    with pytest.raises(ValueError):
        profile.run("ftp://example.com")
    with pytest.raises(ValueError):
        profile.run("")


def test_main_no_args_returns_2():
    assert profile.main([]) == 2


def test_compact_lines_render(extracted):
    res = {**extracted, "url": "u", "final_url": "u", "http_status": 200,
           "blocked": False, "rendered": False, "note": "", "next_steps": ["x"]}
    lines = profile._compact_lines(res)
    assert any("Ada Lovelace" in l for l in lines)
    assert any("SELF-DECLARED" in l for l in lines)


@pytest.mark.network
def test_run_live_linkedin_style_page():
    res = profile.run("https://github.com/torvalds")
    assert res["http_status"] == 200


@pytest.mark.parametrize("name,masked", [
    ("***** ********** ******", True),      # LinkedIn logged-out redaction
    ("**** ** ****** ****", True),
    ("Datasette", False),
    ("AT&T", False),
    ("3M", False),
    ("Company *", False),                    # a real name with one asterisk
])
def test_masked_org_names_detected(name, masked):
    assert profile._is_masked(name) is masked


def test_masked_employers_are_dropped_from_jsonld():
    page = """<script type="application/ld+json">
    {"@type":"Person","name":"X","worksFor":[
      {"@type":"Organization","name":"Datasette"},
      {"@type":"Organization","name":"***** ********** ******"}]}
    </script>"""
    orgs = profile.extract(page)["identity"]["works_for"]
    assert [o["name"] for o in orgs] == ["Datasette"]


@pytest.mark.parametrize("addr,ok", [
    ("real.person@acme.dev", True),
    ("contact@cagancalidag.com", True),
    ("email@domain.tld", False),          # contact-form placeholder
    ("your@email.com", False),
    ("john.doe@example.com", False),
    ("no-reply@acme.dev", False),
    ("me@acme.dev", True),
    ("info@acme.dev", True),
    ("someone@acme.invalid", False),
])
def test_placeholder_emails_rejected(addr, ok):
    assert profile._plausible_email(addr) is ok


def test_decode_cfemail():
    """Cloudflare's email protection is a one-byte XOR; decoding it is the
    difference between finding a contact address and reporting none."""
    token = "93f0fcfde7f2f0e7d3f0f2f4f2fdf0f2fffaf7f2f4bdf0fcfe"
    assert profile.decode_cfemail(token) == "contact@cagancalidag.com"
    assert profile.decode_cfemail("zz") == ""
    assert profile.decode_cfemail("") == ""


def test_mailto_and_tel_links_are_captured():
    html = ('<a href="mailto:me@acme.dev?subject=hi">write</a>'
            '<a href="tel:+905321234567">call</a>')
    res = profile.extract(html, region="TR")
    assert "me@acme.dev" in res["emails"]
    assert res["phones"][0]["e164"] == "+905321234567"
    assert res["phones"][0]["confidence"] == "high"


def test_cfemail_address_is_extracted():
    html = ('<a class="__cf_email__" '
            'data-cfemail="93f0fcfde7f2f0e7d3f0f2f4f2fdf0f2fffaf7f2f4bdf0fcfe">'
            '[email protected]</a>')
    assert "contact@cagancalidag.com" in profile.extract(html)["emails"]


def test_internal_links_are_recorded_for_crawling():
    html = ('<a href="/pages/contact.html">Contact</a>'
            '<a href="/pages/cv.html">CV</a>'
            '<a href="https://github.com/someone">gh</a>')
    res = profile.extract(html, base_url="https://acme.dev/")
    assert "https://acme.dev/pages/contact.html" in res["internal_links"]
    assert "https://acme.dev/pages/cv.html" in res["internal_links"]
    assert all("github.com" not in u for u in res["internal_links"])


@pytest.mark.parametrize("title,name", [
    ("Çağan Efe Çalıdağ (@caganefecalidag) on X", "Çağan Efe Çalıdağ"),
    ("Bill Gates - Gates Foundation | LinkedIn", "Bill Gates"),
    ("Dan – Medium", "Dan"),
    ("@onlyahandle", ""),
])
def test_clean_title_name(title, name):
    assert profile.clean_title_name(title) == name



@pytest.mark.parametrize("url,ok", [
    ("https://acme.dev/contact", True),
    ("https://acme.dev/pages/cv.html", True),
    ("https://acme.dev/impressum", True),
    ("https://acme.dev/iletisim", True),
    ("https://acme.dev/blog/post-42", False),
])
def test_contact_page_detection(url, ok):
    assert bool(profile.CONTACT_PAGE_RE.search(url)) is ok
