# Import the Flask application instance and SQLAlchemy database object
# from the main application file.
# This ensures the same app configuration and models are used.
from main import app, db

# Create an application context manually.
# Flask requires an app context to access configuration, database bindings,
# and other app-specific resources outside of a running server.
with app.app_context():
    # Create all database tables defined by SQLAlchemy models.
    # This scans all db.Model subclasses (e.g., User)
    # and creates the corresponding tables in the connected database
    # if they do not already exist.
    db.create_all()
