# 🖋️ Digital Document Signing and Verification System

A Flask web application that allows users to:
- Sign documents or tickets using their private key & certificate
- Generate signed PDF files
- Verify uploaded signed PDFs to ensure authenticity

This project uses:
- Python 3
- Flask
- Cryptography library for digital signatures
- ReportLab for PDF generation
- PyPDF2 for PDF parsing

---

## 🚀 **Features**

✅ User login & session management  
✅ Sign a document: creates a PDF containing the document text, its digital signature, and the signer’s certificate  
✅ Verify a signed PDF: checks the digital signature against the embedded certificate  
✅ Stores user-specific private keys and certificates in a `certs/` folder  
✅ Simple web interface

---


---

## ⚙ **Installation & Setup**

1. **Clone this repository:**
```bash
git clone https://github.com/AditiAdhikari02/Digital-Ticketing-System.git
cd Digital-Ticketing-System
```


2. **Create a virtual environment (optional but recommended)::**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```


