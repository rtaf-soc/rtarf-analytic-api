from db import Base, engine

# WARNING: This will delete your current table and all its data!
Base.metadata.drop_all(bind=engine)
print("Dropped all tables!")
