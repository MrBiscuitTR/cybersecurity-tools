import pytest

from osint import vehicle


def test_validate_vin_ok():
    v = vehicle.validate_vin("1HGCM82633A004352")
    assert v["check_digit_ok"] is True
    assert v["wmi"] == "1HG"
    assert v["model_year_candidates"] == [2003]


def test_validate_vin_normalizes_case_and_spaces():
    assert vehicle.validate_vin(" 1hgcm8-2633a004352 ")["vin"] == "1HGCM82633A004352"


def test_validate_vin_detects_bad_check_digit():
    v = vehicle.validate_vin("1HGCM82613A004352")   # 9th char changed
    assert v["check_digit_ok"] is False
    assert v["check_digit_expected"] == "3"


@pytest.mark.parametrize("bad", [
    "", "SHORT", "1HGCM82633A00435",          # 16 chars
    "1HGCM82633A0043521",                     # 18 chars
    "1HGCM8I633A004352",                      # contains I
    "1HGCM8O633A004352",                      # contains O
    "1HGCM8Q633A004352",                      # contains Q
])
def test_validate_vin_rejects(bad):
    with pytest.raises(ValueError):
        vehicle.validate_vin(bad)


@pytest.mark.parametrize("code,expected", [
    ("3", [2003]),          # 2033 is in the future -> dropped
    ("A", [1980, 2010]),    # genuinely ambiguous
    ("P", [1993, 2023]),
    ("0", []),              # never used
    ("I", []),
])
def test_vin_year_candidates(code, expected):
    assert vehicle._vin_year_candidates(code, current_year=2026) == expected


def test_turkish_plate_province():
    out = vehicle.decode_plate("34 ABC 123", country="TR")
    assert out["matches"]["TR"]["province"] == "İstanbul"
    assert out["matches"]["TR"]["province_code"] == "34"


def test_turkish_plate_all_provinces_present():
    assert len(vehicle.TR_PROVINCES) == 81
    assert vehicle.TR_PROVINCES["06"] == "Ankara"
    assert vehicle.TR_PROVINCES["35"] == "İzmir"


def test_turkish_plate_invalid_province_code():
    assert "TR" not in vehicle.decode_plate("99 ABC 123", country="auto")["matches"]


@pytest.mark.parametrize("plate,year,period_word", [
    ("AB12 CDE", 2012, "March"),        # 01-49 -> March-August
    ("AB62 CDE", 2012, "September"),    # 51-99 -> Sept of (year-50)
])
def test_uk_plate_age_identifier(plate, year, period_word):
    m = vehicle.decode_plate(plate, country="GB")["matches"]["GB"]
    assert m["first_registered_year"] == year
    assert period_word in m["first_registered_period"]
    assert m["area_code"] == "AB"
    assert "Anglia" in m["region"]


def test_german_plate_district():
    m = vehicle.decode_plate("HH AB 123", country="DE")["matches"]["DE"]
    assert m["district"] == "Hamburg"


def test_owner_lookup_is_refused_with_lawful_routes():
    out = vehicle.decode_plate("34 ABC 123")
    assert out["owner_lookup"]["available"] is False
    assert "DPPA" in out["owner_lookup"]["reason"]
    assert len(out["owner_lookup"]["lawful_routes"]) >= 3


def test_decode_plate_rejects_bad_input():
    with pytest.raises(ValueError):
        vehicle.decode_plate("")
    with pytest.raises(ValueError):
        vehicle.decode_plate("34 ABC 123", country="ZZ")


def test_run_requires_input():
    with pytest.raises(ValueError):
        vehicle.run()


def test_main_no_args_returns_2():
    assert vehicle.main([]) == 2


@pytest.mark.network
def test_decode_vin_live():
    res = vehicle.decode_vin("1HGCM82633A004352")
    assert res["decoded"].get("Make", "").upper() == "HONDA"
