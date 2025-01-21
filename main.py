from fastapi import FastAPI, HTTPException, Depends, status, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Session, create_engine, SQLModel, Field, Relationship
from pydantic import EmailStr, BaseModel, condecimal
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os
from typing import Optional, List
from decimal import Decimal

# Configuration de la base de données
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sqlite_file_name = os.path.join(BASE_DIR, "database.db")
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args, echo=True)

# Configuration JWT
SECRET_KEY = "votre_clé_secrète_très_longue_et_complexe"  # Dans un vrai projet, utilisez une variable d'environnement
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configuration de l'authentification OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_db_and_tables():
    try:
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
    balance: Decimal = Field(default=Decimal("0.00"), decimal_places=2)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    user: Optional["User"] = Relationship(back_populates="account", sa_relationship_kwargs={"uselist": False})
    transactions: List["Transaction"] = Relationship(back_populates="account")

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: EmailStr = Field(unique=True, index=True)
    password: str
    account: Optional[BankAccount] = Relationship(back_populates="user", sa_relationship_kwargs={"uselist": False})

class Transaction(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    amount: Decimal = Field(decimal_places=2)
    type: str = Field(max_length=20)  # "deposit" ou "withdrawal"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    account_id: int = Field(foreign_key="bankaccount.id")
    account: "BankAccount" = Relationship(back_populates="transactions")

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TransactionCreate(BaseModel):
    amount: condecimal(gt=Decimal("0.00"), decimal_places=2)  # Montant doit être positif

class TransactionResponse(BaseModel):
    id: int
    amount: Decimal
    type: str
    created_at: datetime

class BankAccountResponse(BaseModel):
    balance: Decimal
    created_at: datetime
    transactions: List[TransactionResponse] = []

class UserResponse(BaseModel):
    id: int
    email: str
    account: BankAccountResponse

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
    user_id: Optional[int] = None

class TransferCreate(BaseModel):
    recipient_email: EmailStr
    amount: condecimal(gt=Decimal("0.00"), decimal_places=2)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

@app.on_event("startup")
async def on_startup():
    create_db_and_tables()

@app.on_event("shutdown")
async def on_shutdown():
    engine.dispose()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Identifiants invalides",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        if email is None or user_id is None:
            raise credentials_exception
        token_data = TokenData(email=email, user_id=user_id)
    except JWTError:
        raise credentials_exception
    
    user = session.query(User).filter(User.email == token_data.email).first()
    if user is None:
        raise credentials_exception
    return user

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

@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session)
):
    user = session.query(User).filter(User.email == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "user_id": user.id},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/me", response_model=UserResponse)
async def read_users_me(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    bank_account = session.query(BankAccount).filter(BankAccount.user_id == current_user.id).first()
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        account=BankAccountResponse(
            balance=bank_account.balance,
            created_at=bank_account.created_at,
            transactions=[
                TransactionResponse(
                    id=t.id,
                    amount=t.amount,
                    type=t.type,
                    created_at=t.created_at
                ) for t in bank_account.transactions
            ]
        )
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
                    created_at=user.account.created_at,
                    transactions=[
                        TransactionResponse(
                            id=t.id,
                            amount=t.amount,
                            type=t.type,
                            created_at=t.created_at
                        ) for t in user.account.transactions
                    ]
                )
            ) for user in users
        ]
    except Exception as e:
        print(f"Erreur lors de la récupération des utilisateurs: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la récupération des utilisateurs"
        )

@app.post("/deposit", response_model=UserResponse)
async def deposit_money(
    transaction: TransactionCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    try:
        # Récupérer le compte bancaire de l'utilisateur
        bank_account = (
            session.query(BankAccount)
            .filter(BankAccount.user_id == current_user.id)
            .first()
        )
        
        if not bank_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Compte bancaire non trouvé"
            )
        
        # Créer la transaction
        new_transaction = Transaction(
            amount=transaction.amount,
            type="deposit",
            account_id=bank_account.id
        )
        session.add(new_transaction)
        
        # Mettre à jour le solde
        bank_account.balance += transaction.amount
        
        session.commit()
        session.refresh(bank_account)
        session.refresh(new_transaction)
        
        return UserResponse(
            id=current_user.id,
            email=current_user.email,
            account=BankAccountResponse(
                balance=bank_account.balance,
                created_at=bank_account.created_at,
                transactions=[
                    TransactionResponse(
                        id=t.id,
                        amount=t.amount,
                        type=t.type,
                        created_at=t.created_at
                    ) for t in bank_account.transactions
                ]
            )
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        print(f"Erreur lors du dépôt: {str(e)}")
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors du dépôt: {str(e)}"
        )

@app.post("/transfer", response_model=UserResponse)
async def transfer_money(
    transfer: TransferCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    try:
        # Vérifier que le destinataire existe et n'est pas l'expéditeur
        recipient = session.query(User).filter(User.email == transfer.recipient_email).first()
        if not recipient:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Destinataire non trouvé"
            )
        
        if recipient.id == current_user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Vous ne pouvez pas vous transférer de l'argent à vous-même"
            )
        
        # Récupérer les comptes source et destination
        source_account = (
            session.query(BankAccount)
            .filter(BankAccount.user_id == current_user.id)
            .first()
        )
        
        destination_account = (
            session.query(BankAccount)
            .filter(BankAccount.user_id == recipient.id)
            .first()
        )
        
        if not source_account or not destination_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Compte bancaire non trouvé"
            )
        
        # Vérifier que le compte source a assez d'argent
        if source_account.balance < transfer.amount:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Solde insuffisant pour effectuer ce transfert"
            )
        
        # Créer la transaction de débit
        debit_transaction = Transaction(
            amount=transfer.amount,
            type="withdrawal",
            account_id=source_account.id
        )
        
        # Créer la transaction de crédit
        credit_transaction = Transaction(
            amount=transfer.amount,
            type="deposit",
            account_id=destination_account.id
        )
        
        # Mettre à jour les soldes
        source_account.balance -= transfer.amount
        destination_account.balance += transfer.amount
        
        # Sauvegarder les changements
        session.add(debit_transaction)
        session.add(credit_transaction)
        session.commit()
        
        # Rafraîchir les données
        session.refresh(source_account)
        session.refresh(debit_transaction)
        
        return UserResponse(
            id=current_user.id,
            email=current_user.email,
            account=BankAccountResponse(
                balance=source_account.balance,
                created_at=source_account.created_at,
                transactions=[
                    TransactionResponse(
                        id=t.id,
                        amount=t.amount,
                        type=t.type,
                        created_at=t.created_at
                    ) for t in source_account.transactions
                ]
            )
        )
        
    except HTTPException:
        session.rollback()
        raise
    except Exception as e:
        session.rollback()
        print(f"Erreur lors du transfert: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors du transfert: {str(e)}"
        )