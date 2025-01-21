from fastapi import FastAPI, HTTPException, Depends, status
from sqlmodel import Session, create_engine, SQLModel, Field
from pydantic import EmailStr, BaseModel
from passlib.context import CryptContext
import os

# Assurez-vous que le fichier de base de données est créé dans le bon répertoire
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sqlite_file_name = os.path.join(BASE_DIR, "database.db")
sqlite_url = f"sqlite:///{sqlite_file_name}"

# Configuration de l'engine avec des paramètres optimisés
connect_args = {
    "check_same_thread": False,
    "timeout": 30
}
engine = create_engine(sqlite_url, connect_args=connect_args, echo=True)

def create_db_and_tables():
    try:
        SQLModel.metadata.create_all(engine)
        print("Base de données initialisée avec succès")
    except Exception as e:
        print(f"Erreur lors de l'initialisation de la base de données: {e}")
        raise

def get_session():
    try:
        session = Session(engine)
        yield session
    finally:
        session.close()

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: EmailStr = Field(index=True, max_length=255, unique=True)
    password: str = Field(max_length=255)

class UserCreate(BaseModel):
    email: EmailStr
    password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

@app.on_event("startup")
async def on_startup():
    create_db_and_tables()

@app.on_event("shutdown")
async def on_shutdown():
    # Fermer proprement la connexion à la base de données
    engine.dispose()

@app.post("/register", response_model=User, status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate, session: Session = Depends(get_session)):
    # Vérifier si l'email existe déjà
    existing_user = session.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Un utilisateur avec cet email existe déjà"
        )
    
    # Créer le nouvel utilisateur avec mot de passe haché
    db_user = User(
        email=user.email,
        password=pwd_context.hash(user.password)
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user