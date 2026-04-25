# 1 — Run once (after training in Colab, locally, or CI)
from preprocess import fit_and_save
fit_and_save("Obfuscated-MalMem2022.parquet", artifacts_dir="./artifacts")

# 2 — Application startup
from inference import MalwareDetector
detector = MalwareDetector.load("./artifacts/winner_LightGBM.joblib", "./artifacts")

# 3 — Per-scan prediction
result = detector.predict_dict(volatility_snapshot_dict)
# → {"label": 1, "proba": 0.97, "verdict": "MALWARE", "confidence": "HIGH", ...}