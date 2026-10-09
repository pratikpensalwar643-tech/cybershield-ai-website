# AI Cyber Threat Prediction – Flask + MySQL + ML + Login

## Included
- Role-based access: normal users cannot view scan history; developer accounts can view the developer history page.
- Login page with username/password
- Passwords stored as secure hashes, not plain text
- Flask session authentication
- Logout
- Protected dashboard and API endpoints
- TF-IDF + Logistic Regression demo ML model
- MySQL scan history
- Live dashboard statistics
- MySQL connection status

## Setup
1. Install MySQL Server and remember the root password.
2. In Command Prompt, open this folder.
3. Activate the virtual environment:
   venv\Scripts\activate
4. Install dependencies:
   python -m pip install -r requirements.txt
5. Set your MySQL password for this Command Prompt session:
   set DB_PASSWORD=YOUR_MYSQL_PASSWORD
   Optional:
   set DB_USER=root
   set DB_HOST=127.0.0.1
   set DB_NAME=cyber_threat_db
6. Create your first login user:
   python create_user.py
7. Start the server:
   python app.py
8. Open:
   http://127.0.0.1:5000/login

The app creates the database and tables automatically.

## Login
Do NOT use a hard-coded password. Run create_user.py to choose your own username and password.

## Security note
This is suitable as a college/project prototype. For production deployment, use a strong secret key, HTTPS, CSRF protection, rate limiting, secure cookie settings, and a production WSGI server.

## ML note
The included classifier is a small classroom/demo model. For a real cybersecurity product, train and evaluate on a properly labelled dataset and report precision, recall, F1-score and confusion matrix.

## Roles
When running create_user.py, choose:
- user: can use the threat scanner/dashboard but cannot view scan history.
- developer: can use the dashboard and access /developer to view scan history.

The scan history API is server-side protected, so hiding the button alone is not the security control.
