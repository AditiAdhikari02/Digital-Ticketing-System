from web import app, db, Event

with app.app_context():
    # Add your events
    event1 = Event(name="Event 1", date="2025-08-15", description="Sample event 1")
    event2 = Event(name="Event 2", date="2025-09-01", description="Sample event 2")

    db.session.add_all([event1, event2])
    db.session.commit()

    print("✅ Events added successfully!")
