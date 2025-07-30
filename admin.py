from web import db, app, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Change these values as needed
    username = 'admin'
    password = 'admin123'   # Change this to a strong password

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        print(f"⚠️ User '{username}' already exists.")
    else:
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        print(f"✅ Admin user '{username}' created successfully!")
