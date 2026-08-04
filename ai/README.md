# AI Anomaly Detection Engine

This directory will contain the behavior DNA profiling and anomaly detection models.

## AI Technology Stack
* **Scikit-learn**: Isolation Forest model for unsupervised anomaly detection.
* **Pandas**: Feature extraction and data formatting.
* **NumPy**: Numeric operations and distance scoring.

## Planned Features
* **Behavior DNA Profiles**: A rolling baseline representing normal activity (e.g. median daily network uploads, standard working hours boundary).
* **Anomalous Event Detection**: The Isolation Forest model calculates outlier status, which is then fed into the backend's Correlation Engine.
