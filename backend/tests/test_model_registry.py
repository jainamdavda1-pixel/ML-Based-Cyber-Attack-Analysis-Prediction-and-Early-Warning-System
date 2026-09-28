import pytest
import numpy as np
from app.ml.model_registry import model_registry

def test_model_readiness():
    readiness = model_registry.get_readiness()
    assert "cicids2017" in readiness
    assert "unsw-nb15" in readiness
    assert readiness["cicids2017"]["ready"] is True
    assert readiness["unsw-nb15"]["ready"] is True
    assert len(readiness["cicids2017"]["classes"]) == 15
    assert len(readiness["unsw-nb15"]["classes"]) == 10

def test_cicids_pipeline_inference():
    pipeline = model_registry.get_pipeline("cicids2017")
    assert pipeline.is_ready() is True
    dummy_input = np.zeros((1, 70), dtype=np.float32)
    probs = pipeline.predict_probabilities(dummy_input)
    assert probs.shape == (1, 15)
    assert np.isclose(np.sum(probs[0]), 1.0, atol=1e-4)

def test_unsw_pipeline_inference():
    pipeline = model_registry.get_pipeline("unsw-nb15")
    assert pipeline.is_ready() is True
    dummy_input = np.zeros((1, 42), dtype=np.float32)
    probs_bin = pipeline.predict_binary_probabilities(dummy_input)
    assert probs_bin.shape == (1, 2)
    probs_multi = pipeline.predict_multi_probabilities(dummy_input)
    assert probs_multi.shape == (1, 10)
