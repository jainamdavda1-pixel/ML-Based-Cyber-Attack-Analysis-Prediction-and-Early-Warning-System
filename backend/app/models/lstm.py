import logging

logger = logging.getLogger(__name__)

class LSTMSequenceModelWrapper:
    def __init__(self):
        self.loaded = False

    def is_loaded(self) -> bool:
        return self.loaded

    def predict_sequence(self, sequence_data: list):
        if not self.loaded:
            raise RuntimeError("LSTM Sequence Model artifact is not configured.")
        return []

lstm_model_wrapper = LSTMSequenceModelWrapper()
