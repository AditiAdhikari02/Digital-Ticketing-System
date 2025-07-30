from flask import Flask, render_template, request, redirect, session, send_file, url_for
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.exceptions import InvalidSignature
from PyPDF2 import PdfReader
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
import qrcode
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from cryptography import x509
from flask import Flask, request, send_file
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

import base64
import os

# ---------------------------------------
# Flask app setup
# ---------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key-here'  # <-- Add your secret key here
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
print("Database path:", os.path.abspath("site.db"))
db = SQLAlchemy(app)

@app.context_processor
def inject_datetime():
    return {'datetime': datetime}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    certificate = db.Column(db.Text)  # Contains PEM-formatted public key

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date = db.Column(db.String(20), nullable=False)  # You can use DateTime later

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Valid')  # ✅ required column
    certificate_filename = db.Column(db.String(120), nullable=True)
    qr_filename = db.Column(db.String(120), nullable=True)
    seat_number = db.Column(db.String(20), nullable=True)
    purchase_date = db.Column(db.String(20), nullable=True)


# ---------------------------------------
# Directory paths
# ---------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.path.join(BASE_DIR, "certs")
TICKET_DIR = os.path.join(BASE_DIR, "tickets")
EVENTS_FILE = os.path.join(BASE_DIR, "events.json")
REVOKED_CERTS_FILE = "revoked_users.txt"  # Ensure this path is consistent

os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(TICKET_DIR, exist_ok=True)

# ---------------------------------------
# Helper functions
# ---------------------------------------

def revoke_certificate(username):
    with open(REVOKED_CERTS_FILE, "a") as f:
        f.write(username + "\n")

def is_revoked(username):
    if not os.path.exists(REVOKED_CERTS_FILE):
        return False
    with open(REVOKED_CERTS_FILE, "r") as f:
        revoked_users = [line.strip() for line in f.readlines()]
    return username in revoked_users

def get_ticket_status(ticket):
    if ticket.status == 'Valid':
        return "Valid"
    elif ticket.status == 'Revoked':
        return "Revoked"
    elif ticket.status == 'Expired':
        return "Expired"
    else:
        return "Unknown"


def generate_certificate(username):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"NP"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Bagmati"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Kathmandu"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Digital Ticketing Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(public_key) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.utcnow()) \
        .not_valid_after(datetime.utcnow() + timedelta(days=365)) \
        .sign(private_key, hashes.SHA256())

    # Save key and cert files (optional)
    with open(os.path.join(CERT_DIR, f"{username}_key.pem"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()  # decode bytes to string

    with open(os.path.join(CERT_DIR, f"{username}_cert.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert_pem  # Return the PEM string

# ---------------------------------------
# Routes
# ---------------------------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        # Check if user exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', message="Username already exists.")

        hashed_password = generate_password_hash(password)

        # Generate certificate (and private key saved on server)
        cert_pem = generate_certificate(username)

        # Save the certificate PEM in the user table
        new_user = User(username=username, password=hashed_password, certificate=cert_pem)
        db.session.add(new_user)
        db.session.commit()

        return redirect('/login')

    return render_template('register.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        signature_b64 = request.form.get("signature")

        if not username or not password:
            return render_template("login.html", message="Missing fields", username=username)

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            return render_template("login.html", message="Invalid credentials", username=username)

        '''try:
            certificate = x509.load_pem_x509_certificate(user.certificate.encode())
            public_key = certificate.public_key()
            challenge = base64.b64decode(session.get("challenge"))
            signature = base64.b64decode(signature_b64)

            public_key.verify(
                signature,
                challenge,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

        except InvalidSignature:
            return render_template("login.html", message="Signature verification failed", username=username)
        except Exception as e:
            return render_template("login.html", message=f"Error: {str(e)}", username=username)'''

        session["user"] = username
        return redirect("/dashboard")

    # GET request – generate a challenge
    challenge_bytes = os.urandom(32)
    challenge_b64 = base64.b64encode(challenge_bytes).decode()
    session["challenge"] = challenge_b64
    return render_template("login.html", challenge=challenge_b64)

@app.route('/dashboard')
def dashboard():
    username = session.get('user')
    if not username:
        return redirect('/login')  # redirect if user not logged in

    user = User.query.filter_by(username=username).first()
    if not user:
        return redirect('/login')  # user not found in DB

    events = Event.query.all()
    tickets = Ticket.query.filter_by(user_id=user.id).all()

    # Compute ticket status for each ticket
    ticket_statuses = {}
    for ticket in tickets:
        cert_path = os.path.join(CERT_DIR, f"{username}_cert.pem")

        if get_ticket_status(ticket) == "Revoked":
            status = "Revoked"
        elif not os.path.exists(cert_path):
            status = "Certificate Missing"
        else:
            try:
                with open(cert_path, "rb") as f:
                    cert = x509.load_pem_x509_certificate(f.read())
                now = datetime.utcnow()
                if not (cert.not_valid_before <= now <= cert.not_valid_after):
                    status = "Expired"
                else:
                    status = "Valid"
            except Exception:
                status = "Invalid Certificate"

        ticket_statuses[ticket.id] = status

    return render_template(
        'dashboard.html',
        username=username,
        events=events,
        tickets=tickets,
        ticket_statuses=ticket_statuses
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ---------------------------
# Admin routes
# ---------------------------
@app.route('/add_event', methods=['GET', 'POST'])
def add_event():
    if 'user' not in session or session['user'] != 'admin':
        return redirect('/login')
    if request.method == 'POST':
        name = request.form['name']
        date = request.form['date']
        description = request.form.get('description', '')  # if you want description
        new_event = Event(name=name, date=date, description=description)
        db.session.add(new_event)
        db.session.commit()
        return redirect('/dashboard')
    return render_template('add_event.html')

@app.route('/revoke_cert')
def revoke_cert():
    if 'user' not in session:
        return redirect('/login')
    username = session['user']
    revoke_certificate(username)
    session.clear()
    return f"✅ Certificate for user '{username}' has been revoked. <br><a href='/'>Go to Home</a>"


@app.route('/revoked_users')
def revoked_users():
    if 'user' not in session or session['user'] != 'admin':
        return redirect(url_for('login'))

    revoked_list = []
    if os.path.exists(REVOKED_CERTS_FILE):
        with open(REVOKED_CERTS_FILE, 'r') as f:
            revoked_list = [line.strip() for line in f if line.strip()]

    return render_template('revoked_users.html', revoked=revoked_list)


@app.route('/unrevoke/<username>')
def unrevoke(username):
    if 'user' not in session or session['user'] != 'admin':
        return redirect(url_for('login'))

    if os.path.exists(REVOKED_CERTS_FILE):
        with open(REVOKED_CERTS_FILE, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]

        # Remove all instances of the username
        lines = [line for line in lines if line != username]

        with open(REVOKED_CERTS_FILE, 'w') as f:
            for line in lines:
                f.write(line + '\n')

    return redirect(url_for('revoked_users'))

# ---------------------------
# Ticket routes
# ---------------------------
@app.route('/purchase_ticket/<event_name>', methods=['GET', 'POST'])
def purchase_ticket(event_name):
    if 'user' not in session:
        return redirect('/login')

    user = User.query.filter_by(username=session['user']).first()
    event = Event.query.filter_by(name=event_name).first()

    if not event:
        return "Event not found", 404

    # Check if user already purchased ticket for this event
    existing_ticket = Ticket.query.filter_by(user_id=user.id, event_id=event.id).first()
    if existing_ticket:
        return render_template('purchase_ticket.html', event=event, message="You already purchased a ticket for this event.")

    if request.method == 'POST':
        # Create a new ticket with status 'Valid'
        new_ticket = Ticket(user_id=user.id, event_id=event.id, status='Valid')
        db.session.add(new_ticket)
        db.session.commit()
        return redirect('/dashboard')

    return render_template('purchase_ticket.html', event=event)


@app.route('/sign_document', methods=['GET', 'POST'])
def sign_document():
    if 'user' not in session:
        return redirect('/login')

    username = session['user']
    key_path = os.path.join(CERT_DIR, f"{username}_key.pem")
    cert_path = os.path.join(CERT_DIR, f"{username}_cert.pem")

    if not os.path.exists(key_path) or not os.path.exists(cert_path):
        return "❌ Key or certificate not found."

    if request.method == 'POST':
        document_text = request.form.get('document_text')
        if not document_text:
            return render_template("sign_document.html", message="Please provide document text.")

        # Load private key and certificate
        with open(key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        with open(cert_path, "r") as f:
            cert_pem = f.read()

        # Sign only the document_text
        signature = private_key.sign(
            document_text.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature_b64 = base64.b64encode(signature).decode()

        # Create the PDF
        pdf_stream = BytesIO()
        c = canvas.Canvas(pdf_stream, pagesize=letter)

        y = 750
        line_height = 15

        c.setFont("Helvetica-Bold", 12)
        c.drawString(100, y, f"Signed Document by {username}")
        y -= line_height * 2

        c.setFont("Helvetica", 10)

        # Mark start of document text
        c.drawString(100, y, "---DOCUMENT TEXT---")
        y -= line_height

        # Write document text
        for line in document_text.splitlines():
            c.drawString(100, y, line)
            y -= line_height

        # Mark end
        y -= line_height
        c.drawString(100, y, "---END DOCUMENT TEXT---")
        y -= line_height

        # Signature block
        y -= line_height
        c.drawString(100, y, "---SIGNATURE---")
        y -= line_height

        for i in range(0, len(signature_b64), 80):
            c.drawString(100, y, signature_b64[i:i+80])
            y -= line_height

        # Certificate block
        y -= line_height
        c.drawString(100, y, "---CERTIFICATE---")
        y -= line_height

        for line in cert_pem.strip().splitlines():
            c.drawString(100, y, line.strip())
            y -= line_height
            if y < 50:
                c.showPage()
                y = 750

        c.save()
        pdf_stream.seek(0)

        return send_file(
            pdf_stream,
            as_attachment=True,
            download_name=f"{username}_signed_document.pdf",
            mimetype='application/pdf'
        )

    return render_template("sign_document.html")




@app.route('/download_ticket/<username>')
def download_ticket(username):
    event_name = request.args.get('event')
    if not event_name:
        return "❌ Event name required."

    if is_revoked(username):
        return "❌ Your certificate has been revoked. Access denied."

    cert_path = os.path.join(CERT_DIR, f"{username}_cert.pem")
    if not os.path.exists(cert_path):
        return "❌ Certificate not found."

    with open(cert_path, 'rb') as f:
        cert_pem = f.read().decode()

    issue_time = datetime.now().strftime('%d %B %Y, %I:%M %p')
    ticket_text = f"Ticket for {username} to event '{event_name}' on {issue_time}"

    key_path = os.path.join(CERT_DIR, f"{username}_key.pem")
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(
        ticket_text.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature).decode()

    qr = qrcode.make(f"{ticket_text}\n{signature_b64}")
    qr_stream = BytesIO()
    qr.save(qr_stream, format='PNG')
    qr_stream.seek(0)

    # ✅ REPLACING old text ticket with PDF generation:
    ticket_stream = BytesIO()
    c = canvas.Canvas(ticket_stream, pagesize=letter)

    y = 750
    line_height = 15

    # Write ticket text (split lines if long)
    for line in ticket_text.split('\n'):
        c.drawString(100, y, line)
        y -= line_height

    y -= line_height
    c.drawString(100, y, "---SIGNATURE---")
    y -= line_height

    # Write signature in lines of max 80 chars (base64 is long)
    for i in range(0, len(signature_b64), 80):
        c.drawString(100, y, signature_b64[i:i + 80])
        y -= line_height

    y -= line_height
    c.drawString(100, y, "---CERTIFICATE---")
    y -= line_height

    # Read the certificate file and write line by line
    cert_path = os.path.join(CERT_DIR, f"{username}_cert.pem")
    with open(cert_path, "r") as cert_file:
        cert_lines = cert_file.readlines()

    for line in cert_lines:
        c.drawString(100, y, line.strip())
        y -= line_height

    c.save()
    ticket_stream.seek(0)

    return send_file(ticket_stream,
                     as_attachment=True,
                     download_name=f"{username}_{event_name}_ticket.pdf",
                     mimetype='application/pdf')

@app.route('/verify_ticket', methods=['GET', 'POST'])
def verify_ticket():
    result = None
    if request.method == 'POST':
        uploaded_file = request.files.get('ticket_file')
        if uploaded_file and uploaded_file.filename.endswith('.pdf'):
            try:
                reader = PdfReader(uploaded_file)
                text = ''
                for page in reader.pages:
                    extracted = page.extract_text()
                    if extracted:
                        text += extracted + '\n'

                lines = text.splitlines()

                # Find indices
                doc_start = lines.index("---DOCUMENT TEXT---") + 1
                doc_end = lines.index("---END DOCUMENT TEXT---")
                sign_index = lines.index("---SIGNATURE---")
                cert_index = lines.index("---CERTIFICATE---")

                if doc_start >= doc_end or sign_index <= doc_end or cert_index <= sign_index:
                    result = "❌ Verification failed: Missing or invalid markers."
                    return render_template('verify_ticket.html', result=result)

                # Extract parts
                document_text_lines = lines[doc_start:doc_end]
                signature_lines = lines[sign_index+1:cert_index]
                certificate_lines = lines[cert_index+1:]

                document_text = '\n'.join(document_text_lines).strip()
                signature_b64 = ''.join(signature_lines).strip()
                certificate_pem = '\n'.join(certificate_lines).strip()

                # Load cert and verify
                cert = x509.load_pem_x509_certificate(certificate_pem.encode())
                public_key = cert.public_key()
                signature = base64.b64decode(signature_b64)

                public_key.verify(
                    signature,
                    document_text.encode(),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                result = "✅ Verification passed: Ticket is valid."

            except InvalidSignature:
                result = "❌ Verification failed: Invalid signature."
            except Exception as e:
                result = f"❌ Verification failed: {str(e)}"
        else:
            result = "❌ Verification failed: Invalid or missing PDF file."

    return render_template('verify_ticket.html', result=result)


# ---------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # 🔥 This creates the tables in the new DB
    app.run(debug=True)


