from fastapi import FastAPI, HTTPException, Depends, status
from sqlmodel import Session, create_engine, SQLModel, Field, Relationship
from pydantic import EmailStr, BaseModel
from passlib.context import CryptContext
import os
from typing import Optional
from datetime import datetime

# Configuration de la base de données
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sqlite_file_name = os.path.join(BASE_DIR, "database.db")
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args, echo=True)

def create_db_and_tables():
    try:
        # On ne supprime plus les tables, on les crée seulement si elles n'existent pas
        SQLModel.metadata.create_all(engine)
        print("Base de données initialisée avec succès")
    except Exception as e:
        print(f"Erreur lors de l'initialisation de la base de données: {e}")

def get_session():
    try:
        session = Session(engine)
        yield session
    finally:
        session.close()

class BankAccount(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    balance: float = Field(default=0.0)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    user: Optional["User"] = Relationship(back_populates="account", sa_relationship_kwargs={"uselist": False})

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: EmailStr = Field(unique=True, index=True)
    password: str
    account: Optional[BankAccount] = Relationship(back_populates="user", sa_relationship_kwargs={"uselist": False})

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class BankAccountResponse(BaseModel):
    balance: float
    created_at: datetime

class UserResponse(BaseModel):
    id: int
    email: str
    account: BankAccountResponse

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

@app.on_event("startup")
async def on_startup():
    create_db_and_tables()

@app.on_event("shutdown")
async def on_shutdown():
    engine.dispose()

@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate, session: Session = Depends(get_session)):
    try:
        # Vérifier si l'email existe déjà
        if session.query(User).filter(User.email == user.email).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Un utilisateur avec cet email existe déjà"
            )
        
        # Créer l'utilisateur
        db_user = User(
            email=user.email,
            password=pwd_context.hash(user.password)
        )
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        
        # Créer le compte bancaire
        bank_account = BankAccount(user_id=db_user.id)
        session.add(bank_account)
        session.commit()
        session.refresh(bank_account)
        
        return UserResponse(
            id=db_user.id,
            email=db_user.email,
            account=BankAccountResponse(
                balance=bank_account.balance,
                created_at=bank_account.created_at
            )
        )
    except Exception as e:
        session.rollback()
        print(f"Erreur lors de l'inscription: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'inscription: {str(e)}"
        )

@app.post("/login", response_model=UserResponse)
def login_user(user: UserLogin, session: Session = Depends(get_session)):
    try:
        # Rechercher l'utilisateur
        db_user = session.query(User).filter(User.email == user.email).first()
        if not db_user or not pwd_context.verify(user.password, db_user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email ou mot de passe incorrect"
            )
        
        # Récupérer le compte bancaire
        bank_account = session.query(BankAccount).filter(BankAccount.user_id == db_user.id).first()
        if not bank_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Compte bancaire non trouvé"
            )
        
        return UserResponse(
            id=db_user.id,
            email=db_user.email,
            account=BankAccountResponse(
                balance=bank_account.balance,
                created_at=bank_account.created_at
            )
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Erreur lors de la connexion: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de la connexion: {str(e)}"
        )

@app.get("/users", response_model=list[UserResponse])
def list_users(session: Session = Depends(get_session)):
    try:
        users = session.query(User).all()
        return [
            UserResponse(
                id=user.id,
                email=user.email,
                account=BankAccountResponse(
                    balance=user.account.balance,
                    created_at=user.account.created_at
                )
            ) for user in users
        ]
    except Exception as e:
        print(f"Erreur lors de la récupération des utilisateurs: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la récupération des utilisateurs"
        )