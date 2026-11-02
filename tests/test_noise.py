import pandas as pd
import pytest
from src.noise import inject_noise
from src.selection import extract_features

def test_seeded_noise_and_copy_safety():
    original=pd.DataFrame([{"record_id":"a","label":"attack"},{"record_id":"b","label":"unknown"}]); before=original.copy(deep=True)
    one,_=inject_noise(original,"duplicate-flooding",.5,5); two,_=inject_noise(original,"duplicate-flooding",.5,5)
    pd.testing.assert_frame_equal(original,before); pd.testing.assert_frame_equal(one,two); assert one.iloc[-1].source_record_id in {"a","b"} and one.iloc[-1].is_synthetic

def test_missing_manifest_and_source_label():
    data=pd.DataFrame([{"record_id":str(i),"label":"source"} for i in range(10)])
    result,manifest=inject_noise(data,"missing-evidence",.2,1); assert len(manifest["removed_record_ids"])==2 and len(result)==8 and set(result.label)=={"source"}

def test_synthetic_labels_are_separate_and_bad_proportion_rejected():
    data=pd.DataFrame([{"record_id":"a","label":"source-attack"}]); result,_=inject_noise(data,"benign-looking",.1,2)
    assert result.iloc[-1].label is None and result.iloc[-1].synthetic_label=="unlabeled_synthetic"
    with pytest.raises(ValueError): inject_noise(data,"missing-evidence",1.1,0)

def test_benign_noise_rows_have_distinct_payloads_and_do_not_corroborate_each_other():
    data=pd.DataFrame([
        {"record_id":"a","timestamp":"2025-01-01T00:00:00Z","host":"host-a","event_type":"10","source":"source-a","original_json":"{\"event\":\"a\"}"},
        {"record_id":"b","timestamp":"2025-01-01T00:10:00Z","host":"host-a","event_type":"10","source":"source-a","original_json":"{\"event\":\"b\"}"},
    ])
    noisy,manifest=inject_noise(data,"benign-looking",1.0,4)
    synthetic=noisy[noisy.is_synthetic.astype(bool)]
    assert len(synthetic)==2
    assert synthetic.original_json.nunique()==2
    assert synthetic.timestamp.notna().all() and synthetic.host.tolist()==["host-a","host-a"]
    assert ("label" not in synthetic or synthetic["label"].isna().all()) and synthetic.synthetic_label.eq("unlabeled_synthetic").all()
    features,_=extract_features(noisy)
    assert features.loc[features.is_synthetic.astype(bool),"feature_corroboration"].eq(0).all()
    assert "not source observations" in manifest["synthetic_field_note"]
