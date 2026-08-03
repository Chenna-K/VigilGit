from database.database import Base, engine
from ..models import user


def create_tables():
    Base.metadata.create_all(bind=engine)
    