# ReconX - AI-Powered Reconnaissance Platform

## 🚀 Quick Start

### Prerequisites
- Python 3.7+
- MongoDB Atlas account (or local MongoDB)

### Installation

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure MongoDB** (Optional)
   - Update `MONGO_URI` in `app.py` with your MongoDB connection string
   - Or leave it as-is to run in offline mode (in-memory storage)

### Running the Application

**Option 1: Using the Batch File (Windows)**
```bash
start_server.bat
```

**Option 2: Using Python Directly**
```bash
python app.py
```

**Option 3: Using Python Module**
```bash
python -m flask run
```

### Accessing the Application

Once the server starts, open your browser and navigate to:

- **Login Page**: http://localhost:5000/login
- **Signup Page**: http://localhost:5000/signup
- **Home/Dashboard**: http://localhost:5000/home
- **Scan Page**: http://localhost:5000/scan
- **Report Page**: http://localhost:5000/report
- **Admin Panel**: http://localhost:5000/admin

### Project Structure

```
Reconx New/
├── app.py                 # Main Flask application
├── model/                 # ML Models
│   ├── model1.py         # Subdomain Discovery
│   ├── model2.py         # Port Scanning
│   └── model3.py         # Technology Fingerprinting
├── tools/                 # Utility tools
├── Templates/            # HTML templates
├── css/                  # Stylesheets
├── js/                   # JavaScript files
├── assets/               # Images and media
└── requirements.txt      # Python dependencies
```

### Features

- **Model 1**: Subdomain Discovery with ML Classification
- **Model 2**: Port Scanning & Service Detection
- **Model 3**: Technology Fingerprinting & CVE Detection

### Notes

- The application runs on port **5000** by default
- MongoDB connection is optional - app works in offline mode
- All static files (CSS, JS, images) are served by Flask
- Use Flask routes instead of opening HTML files directly
