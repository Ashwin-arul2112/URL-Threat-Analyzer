import os
import subprocess
import sys
import time
import requests

MODEL_PATH = os.path.join("model", "phiusiil_smartphish.pkl")
DATASET_PATH = os.path.join("data", "phish_url.csv")
TRAIN_SCRIPT = os.path.join("src", "model_training.py")
FLASK_APP = os.path.join("web_app", "app.py")
MONGO_URI = "mongodb://localhost:27017/"
TEST_URL = "https://example.com"  # used to verify live scan connectivity

def train_model():
    """Train the PhiUSIIL model if it doesn’t exist."""
    if os.path.exists(MODEL_PATH):
        print(f"[✅] Model already exists at: {MODEL_PATH}")
        return

    if not os.path.exists(DATASET_PATH):
        print(f"[❌] Dataset not found at: {DATASET_PATH}")
        print("    Please ensure your dataset CSV is present before training.")
        sys.exit(1)

    print("[⚙️] Training model using PhiUSIIL dataset...")
    try:
        subprocess.run([sys.executable, TRAIN_SCRIPT], check=True)
        print("[✅] Model training complete and saved in /model directory.")
    except subprocess.CalledProcessError as e:
        print(f"[❌] Model training failed: {e}")
        sys.exit(1)

def check_mongo():
    """Ensure MongoDB is running before continuing."""
    print("[🔍] Checking MongoDB connection...")
    try:
        import pymongo
        client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
        client.server_info()  # test connection
        print("[✅] MongoDB connection verified.")
    except Exception:
        print("[❌] MongoDB is not running or unreachable.")
        print("    ➤ Please start MongoDB before continuing.")
        sys.exit(1)

def launch_flask():
    """Start the Flask web dashboard."""
    if not os.path.exists(FLASK_APP):
        print(f"[❌] Flask app not found at: {FLASK_APP}")
        sys.exit(1)

    print("[🚀] Launching Flask web dashboard...")
    try:
        subprocess.run([sys.executable, FLASK_APP], check=True)
    except KeyboardInterrupt:
        print("\n[🛑] Flask stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"[❌] Flask failed to start: {e}")
        sys.exit(1)

def test_system_health():
    """Perform a quick live scan check after startup."""
    print("[🧠] Running system connectivity test...")
    try:
        response = requests.post("http://127.0.0.1:5000/api/live_scan",
                                 json={"url": TEST_URL}, timeout=8)
        if response.status_code == 200:
            print(f"[✅] Live scan API working correctly for {TEST_URL}")
        else:
            print(f"[⚠️] Live scan API returned status: {response.status_code}")
    except Exception as e:
        print(f"[⚠️] Could not perform live scan check: {e}")

if __name__ == "__main__":
    print("\n==== 🌍 PhiUSIIL SmartPhish Threat Intelligence Launcher ====\n")

    # Step 1: Check model
    train_model()
    time.sleep(0.5)

    # Step 2: Check MongoDB
    check_mongo()
    time.sleep(0.5)

    # Step 3: Start Flask
    print("\n[🟢] All systems ready. Initializing Flask web app...\n")
    time.sleep(1)

    # Launch Flask app
    launch_flask()
