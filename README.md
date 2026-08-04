# ThreatVista

**ThreatVista** is a privacy-first Insider Threat Detection System that monitors endpoint system metadata (file operations, USB usage, login patterns, network uploads) to identify anomalous behavior and calculate employee risk scores without ever inspecting the actual content of their files.

By using machine learning (Isolation Forest) and event correlation, ThreatVista learns each employee's unique **Behavior DNA** and alerts administrators to suspicious activities.

---

## Key Features
* **Privacy-First Metadata Monitoring**: Tracks file actions, processes, and device access without scanning user document contents.
* **Employee Behavior DNA**: Learns unique baseline patterns for each user's regular working hours, network load, and device operations.
* **AI Anomaly Detection**: Employs an Isolation Forest ML model to detect behavioral anomalies.
* **Security Operations Center (SOC) Dashboard**: Provides live charts, timeline grids, employee behavior DNA graphs, and details for explainable risk mitigation.

---

## Project Structure
```
ThreatVista/
├── frontend/             # React (Vite) + Tailwind CSS Dashboard UI
├── backend/              # FastAPI Server + SQLAlchemy Models
├── endpoint_agent/       # Windows Endpoint monitoring client (watchdog, psutil)
├── ai/                   # AI Anomaly Detection model (Isolation Forest, Behavior DNA)
├── database/             # SQLite DB schemas and instances
├── docs/                 # System architecture and workflow documentation
├── requirements.txt      # Python dependencies
└── .gitignore            # Git exclusion patterns
```

---

## Setup & Running Guide

### 1. Prerequisites
* **Node.js** (v18 or higher)
* **Python** (v3.10 or higher)

### 2. Backend Setup
1. Navigate to the backend directory or run from the root.
2. Install Python packages:
   ```bash
   pip install -r requirements.txt
   ```
3. Initialize the database schema:
   ```bash
   python backend/database/db_setup.py
   ```
4. Start the FastAPI development server:
   ```bash
   uvicorn backend.main:app --reload
   ```
   The backend will run on `http://127.0.0.1:8000`.

### 3. Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install Node modules:
   ```bash
   npm install
   ```
3. Start the Vite React development server:
   ```bash
   npm run dev
   ```
   The frontend will run on `http://localhost:5173`.
