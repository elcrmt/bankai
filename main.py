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
import random

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
    account_type: str = Field(default="principal")  # "principal", "epargne", "courant", etc.
    balance: Decimal = Field(default=Decimal("0.00"), decimal_places=2)
    iban: str = Field(default=None, unique=True, index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    user: Optional["User"] = Relationship(back_populates="accounts")
    transactions: List["Transaction"] = Relationship(back_populates="account")

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    password: str
    accounts: List[BankAccount] = Relationship(back_populates="user")

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
    other_account_email: Optional[str] = None  # Email de l'autre compte impliqué

class BankAccountCreate(BaseModel):
    account_type: str = Field(default="principal")

class BankAccountResponse(BaseModel):
    id: int
    account_type: str
    balance: Decimal
    iban: str
    created_at: datetime
    transactions: List[TransactionResponse] = []

class UserResponse(BaseModel):
    id: int
    email: str
    accounts: List[BankAccountResponse]

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
    user_id: Optional[int] = None

class TransferCreate(BaseModel):
    source_iban: str
    recipient_iban: str
    amount: condecimal(gt=Decimal("0.00"), decimal_places=2)

class InternalTransferCreate(BaseModel):
    source_account_id: int
    destination_account_id: int
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

def get_enriched_transactions(session: Session, transactions: List[Transaction], current_user_email: str) -> List[TransactionResponse]:
    enriched_transactions = []
    for t in transactions:
        other_email = None
        if t.type == "withdrawal":
            # Pour un retrait (transfert envoyé), chercher la transaction de dépôt correspondante
            related_deposit = (
                session.query(Transaction)
                .join(BankAccount)
                .join(User)
                .filter(
                    Transaction.type == "deposit",
                    Transaction.amount == t.amount,
                    Transaction.created_at == t.created_at
                )
                .with_entities(User.email)
                .first()
            )
            if related_deposit:
                other_email = related_deposit[0]
        elif t.type == "deposit":
            # Pour un dépôt (transfert reçu), chercher la transaction de retrait correspondante
            related_withdrawal = (
                session.query(Transaction)
                .join(BankAccount)
                .join(User)
                .filter(
                    Transaction.type == "withdrawal",
                    Transaction.amount == t.amount,
                    Transaction.created_at == t.created_at
                )
                .with_entities(User.email)
                .first()
            )
            if related_withdrawal:
                other_email = related_withdrawal[0]
        
        enriched_transactions.append(
            TransactionResponse(
                id=t.id,
                amount=t.amount,
                type=t.type,
                created_at=t.created_at,
                other_account_email=other_email
            )
        )
    return enriched_transactions

def generate_iban():
    country_code = "FR"
    check_digits = str(random.randint(10, 99))
    bank_code = "12345"  # Code banque fixe pour notre banque
    branch_code = str(random.randint(10000, 99999))
    account_number = ''.join([str(random.randint(0, 9)) for _ in range(11)])
    rib_key = str(random.randint(10, 99))
    
    return f"{country_code}{check_digits}{bank_code}{branch_code}{account_number}{rib_key}"

@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate, session: Session = Depends(get_session)):
    try:
        # Vérifier si l'email existe déjà
        if session.query(User).filter(User.email == user.email).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Un utilisateur avec cet email existe déjà"
            )
        
        # Hasher le mot de passe
        hashed_password = pwd_context.hash(user.password)
        
        # Créer l'utilisateur
        db_user = User(
            email=user.email,
            password=hashed_password
        )
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        
        # Créer le compte bancaire principal avec IBAN
        bank_account = BankAccount(
            user_id=db_user.id,
            account_type="principal",
            balance=Decimal("100.00"),
            iban=generate_iban()
        )
        session.add(bank_account)
        session.commit()
        session.refresh(bank_account)
        
        return UserResponse(
            id=db_user.id,
            email=db_user.email,
            accounts=[
                BankAccountResponse(
                    id=bank_account.id,
                    account_type=bank_account.account_type,
                    balance=bank_account.balance,
                    iban=bank_account.iban,
                    created_at=bank_account.created_at,
                    transactions=[]
                )
            ]
        )
    except HTTPException as e:
        session.rollback()
        raise e
    except Exception as e:
        session.rollback()
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
    accounts = session.query(BankAccount).filter(BankAccount.user_id == current_user.id).all()
    
    # Récupérer les transactions triées par date décroissante
    transactions = []
    for account in accounts:
        account_transactions = (
            session.query(Transaction)
            .filter(Transaction.account_id == account.id)
            .order_by(Transaction.created_at.desc())
            .all()
        )
        transactions.extend(account_transactions)
    
    enriched_transactions = get_enriched_transactions(session, transactions, current_user.email)
    
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        accounts=[
            BankAccountResponse(
                id=account.id,
                account_type=account.account_type,
                balance=account.balance,
                iban=account.iban,
                created_at=account.created_at,
                transactions=[t for t in enriched_transactions if t.id in [t.id for t in account.transactions]]
            ) for account in accounts
        ]
    )

@app.get("/users", response_model=list[UserResponse])
def list_users(session: Session = Depends(get_session)):
    try:
        users = session.query(User).all()
        return [
            UserResponse(
                id=user.id,
                email=user.email,
                accounts=[
                    BankAccountResponse(
                        id=account.id,
                        account_type=account.account_type,
                        balance=account.balance,
                        iban=account.iban,
                        created_at=account.created_at,
                        transactions=get_enriched_transactions(session, account.transactions, user.email)
                    ) for account in user.accounts
                ]
            ) for user in users
        ]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la récupération des utilisateurs"
        )

@app.post("/account", response_model=BankAccountResponse)
async def create_account(
    account: BankAccountCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    try:
        # Vérifier si l'utilisateur a déjà un compte de ce type
        existing_account = (
            session.query(BankAccount)
            .filter(
                BankAccount.user_id == current_user.id,
                BankAccount.account_type == account.account_type
            )
            .first()
        )
        
        if existing_account:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Vous avez déjà un compte de type {account.account_type}"
            )
        
        new_account = BankAccount(
            account_type=account.account_type,
            user_id=current_user.id,
            iban=generate_iban()
        )
        session.add(new_account)
        session.commit()
        session.refresh(new_account)
        
        return BankAccountResponse(
            id=new_account.id,
            account_type=new_account.account_type,
            balance=new_account.balance,
            iban=new_account.iban,
            created_at=new_account.created_at,
            transactions=[]
        )
    except HTTPException as he:
        raise he
    except Exception as e:
        session.rollback()
        print(f"Erreur lors de la création du compte: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de la création du compte: {str(e)}"
        )

@app.post("/deposit", response_model=UserResponse)
async def deposit_money(
    transaction: TransactionCreate,
    account_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    try:
        # Récupérer le compte bancaire de l'utilisateur
        bank_account = (
            session.query(BankAccount)
            .filter(BankAccount.id == account_id, BankAccount.user_id == current_user.id)
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
            accounts=[
                BankAccountResponse(
                    id=account.id,
                    account_type=account.account_type,
                    balance=account.balance,
                    iban=account.iban,
                    created_at=account.created_at,
                    transactions=[
                        TransactionResponse(
                            id=t.id,
                            amount=t.amount,
                            type=t.type,
                            created_at=t.created_at
                        ) for t in account.transactions
                    ]
                ) for account in current_user.accounts
            ]
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

@app.post("/transfer", response_model=List[TransactionResponse])
async def transfer_money(
    transfer: TransferCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    try:
        # Vérifier le compte source par IBAN
        source_account = session.query(BankAccount).filter(
            BankAccount.iban == transfer.source_iban,
            BankAccount.user_id == current_user.id
        ).first()
        
        if not source_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Compte source non trouvé ou ne vous appartient pas"
            )
        
        # Vérifier le compte destinataire par IBAN
        recipient_account = session.query(BankAccount).filter(
            BankAccount.iban == transfer.recipient_iban
        ).first()
        
        if not recipient_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Compte destinataire non trouvé"
            )
        
        # Vérifier que l'utilisateur ne transfère pas au même compte
        if source_account.id == recipient_account.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Impossible de transférer de l'argent au même compte"
            )
        
        # Vérifier le solde
        if source_account.balance < transfer.amount:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Solde insuffisant pour effectuer ce transfert"
            )
        
        now = datetime.utcnow()
        
        # Créer les transactions
        debit_transaction = Transaction(
            amount=transfer.amount,
            type="transfer_sent",
            account_id=source_account.id,
            created_at=now
        )
        
        credit_transaction = Transaction(
            amount=transfer.amount,
            type="transfer_received",
            account_id=recipient_account.id,
            created_at=now
        )
        
        # Mettre à jour les soldes
        source_account.balance -= transfer.amount
        recipient_account.balance += transfer.amount
        
        # Sauvegarder les changements
        session.add(debit_transaction)
        session.add(credit_transaction)
        session.commit()
        session.refresh(debit_transaction)
        session.refresh(credit_transaction)
        
        return [
            TransactionResponse(
                id=debit_transaction.id,
                amount=debit_transaction.amount,
                type=debit_transaction.type,
                created_at=debit_transaction.created_at
            ),
            TransactionResponse(
                id=credit_transaction.id,
                amount=credit_transaction.amount,
                type=credit_transaction.type,
                created_at=credit_transaction.created_at
            )
        ]
        
    except HTTPException as e:
        session.rollback()
        raise e
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors du transfert: {str(e)}"
        )

@app.post("/transfer/internal", response_model=UserResponse)
async def internal_transfer(
    transfer: InternalTransferCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    try:
        # Vérifier que les deux comptes appartiennent à l'utilisateur
        source_account = (
            session.query(BankAccount)
            .filter(
                BankAccount.id == transfer.source_account_id,
                BankAccount.user_id == current_user.id
            )
            .first()
        )
        
        destination_account = (
            session.query(BankAccount)
            .filter(
                BankAccount.id == transfer.destination_account_id,
                BankAccount.user_id == current_user.id
            )
            .first()
        )
        
        if not source_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Compte source introuvable"
            )
            
        if not destination_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Compte destination introuvable"
            )
            
        if source_account.id == destination_account.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Impossible de transférer de l'argent vers le même compte"
            )
        
        # Vérifier le solde du compte source
        if source_account.balance < transfer.amount:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Solde insuffisant pour effectuer le transfert"
            )
        
        # Créer les transactions
        debit_transaction = Transaction(
            amount=transfer.amount,
            type="withdrawal",
            account_id=source_account.id
        )
        
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
        
        # Rafraîchir les objets
        session.refresh(source_account)
        session.refresh(destination_account)
        session.refresh(current_user)
        
        # Retourner la réponse avec tous les comptes mis à jour
        return UserResponse(
            id=current_user.id,
            email=current_user.email,
            accounts=[
                BankAccountResponse(
                    id=account.id,
                    account_type=account.account_type,
                    balance=account.balance,
                    iban=account.iban,
                    created_at=account.created_at,
                    transactions=[
                        TransactionResponse(
                            id=t.id,
                            amount=t.amount,
                            type=t.type,
                            created_at=t.created_at
                        ) for t in account.transactions
                    ]
                ) for account in current_user.accounts
            ]
        )
        
    except HTTPException as he:
        raise he
    except Exception as e:
        session.rollback()
        print(f"Erreur lors du transfert interne: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors du transfert interne: {str(e)}"
        )