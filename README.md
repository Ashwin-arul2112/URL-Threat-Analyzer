# URL-Threat-Analyzer

URL Threat Analyzer is a full-stack malicious URL detection system combining a machine-learning model, feature engineering, live WHOIS/HTTP scanning, and an interactive web dashboard.
The application is built with Python, Flask, and MongoDB.

Create a folder named data and model
Inside a data download the dataset from "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset" or your own dataset

**Features :**
- AI URL Classification
- Extracts lexical, structural, and heuristic URL features
- Uses an ensemble ML model trained in model_training.py
- Prediction handled via predict.py
- (Feature logic: feature_extraction.py)

**Live Network Scan :**
- WHOIS lookup
- IP resolution and final URL
- Redirect tracing
- HTTP response latency
- Implemented in live_scan.py.

**Interface :**

Templates include:
index.html (AI Scan / Live Scan)
<img width="1920" height="1020" alt="Screenshot 2025-11-21 175427" src="https://github.com/user-attachments/assets/d085f7c8-109c-4715-8364-a8ca005e0bb0" />

Recent Scans:
<img width="1920" height="1020" alt="Screenshot 2025-11-21 175441" src="https://github.com/user-attachments/assets/0eaeaf7c-2682-4a3d-8f21-eaefdb955a65" />

dashboard.html (statistics and charts)
<img width="1920" height="1020" alt="Screenshot 2025-11-21 175448" src="https://github.com/user-attachments/assets/e755889b-abb6-47ab-a5e0-9dce29ec7fe7" />

batch.html + batch_result.html (CSV batch scanning)
<img width="1920" height="1020" alt="Screenshot 2025-11-21 175452" src="https://github.com/user-attachments/assets/21ec80d7-4199-49b2-8fc6-72935a6db824" />

report_view.html (detailed URL reports)
<img width="1920" height="1020" alt="Screenshot 2025-11-21 182527" src="https://github.com/user-attachments/assets/75f50e00-44a2-445f-a096-5d732598f6e5" />

All pages extend layout.html.

**MongoDB Storage :**
- AI scans and Live scans stored for analytics
- Dashboard metrics generated directly from database
- Batch Processing
- Chunk-based feature extraction using utils.py

**Installation :**

pip install -r requirements.txt

Start MongoDB (local or Atlas), then export the URI:
export MONGODB_URI="mongodb://localhost:27017/threat_analyzer"

Optional model training:
python src/model_training.py

Run the application:
python app.py


**Visit:**

http://127.0.0.1:5000
