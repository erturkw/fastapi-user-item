from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

SQLALCHEMY_DATABASE_URL = (
    "mssql+pyodbc://bedirhan:12345@(localdb)\MSSQLLocalDB/usersdb"
    "?driver=ODBC+Driver+17+for+SQL+Server"
)

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
