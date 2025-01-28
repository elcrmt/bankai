from fastapi import FastAPI, HTTPException, Depends, status, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Session, create_engine, SQLModel, Field, Relationship
from sqlalchemy.orm import joinedload
from sqlalchemy import UniqueConstraint
from pydantic import EmailStr, BaseModel, condecimal
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os
from typing import Optional, List
from decimal import Decimal
import random
from fastapi.middleware.cors import CORSMiddleware

# Configuration de la base de données
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sqlite_file_name = os.path.join(BASE_DIR, "database.db")
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args, echo=True)

# Configuration JWT
SECRET_KEY = "votre_clé_secrète_très_longue_et_complexe"  
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
    closed_at: Optional[datetime] = Field(default=None)  # Date de clôture du compte
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    user: Optional["User"] = Relationship(back_populates="account")
    transactions: List["Transaction"] = Relationship(back_populates="account")

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    password: str
    account: Optional[BankAccount] = Relationship(back_populates="user", sa_relationship_kwargs={"uselist": False})
    beneficiaries: List["Beneficiary"] = Relationship(back_populates="user")

class Beneficiary(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    iban: str = Field(index=True)
    user_id: int = Field(foreign_key="user.id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    user: "User" = Relationship(back_populates="beneficiaries")
    
    __table_args__ = (
        UniqueConstraint('user_id', 'iban', name='unique_user_beneficiary'),
    )

class Transaction(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    amount: Decimal = Field(decimal_places=2)
    type: str = Field(max_length=20)  # "transfer_sent", "transfer_received", "cancellation_sent", "cancellation_received"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    can_cancel_until: Optional[datetime] = Field(default=None)
    related_transaction_id: Optional[int] = Field(default=None)
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
    can_cancel_until: Optional[datetime] = None
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

class BeneficiaryCreate(BaseModel):
    name: str = Field(min_length=1)
    iban: str

class BeneficiaryResponse(BaseModel):
    id: int
    name: str
    iban: str
    created_at: datetime

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

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Autoriser le frontend React
    allow_credentials=True,
    allow_methods=["*"],  # Autoriser toutes les méthodes HTTP
    allow_headers=["*"],  # Autoriser tous les headers
)

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
        print(f"Tentative d'inscription pour l'email: {user.email}")
        
        # Vérifier si l'email existe déjà
        existing_user = session.query(User).filter(User.email == user.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cet email est déjà utilisé"
            )
        
        print("Hachage du mot de passe...")
        # Hasher le mot de passe
        hashed_password = pwd_context.hash(user.password)
        
        print("Création de l'utilisateur...")
        # Créer le nouvel utilisateur
        new_user = User(
            email=user.email,
            password=hashed_password
        )
        session.add(new_user)
        session.flush()  # Pour obtenir l'ID de l'utilisateur
        
        print(f"Utilisateur créé avec l'ID: {new_user.id}")
        print("Création du compte bancaire...")
        
        # Créer un compte principal avec 100€
        iban = generate_iban()
        print(f"IBAN généré: {iban}")
        
        new_account = BankAccount(
            account_type="principal",
            balance=Decimal("100.00"),
            iban=iban,
            user_id=new_user.id
        )
        session.add(new_account)
        session.flush()
        
        print(f"Compte bancaire créé avec l'ID: {new_account.id}")
        print("Création de la transaction initiale...")
        
        # Créer une transaction initiale pour le solde de 100€
        initial_transaction = Transaction(
            amount=Decimal("100.00"),
            type="deposit",
            account_id=new_account.id
        )
        session.add(initial_transaction)
        
        print("Commit des changements...")
        session.commit()
        session.refresh(new_user)
        session.refresh(new_account)
        
        print("Inscription réussie!")
        return UserResponse(
            id=new_user.id,
            email=new_user.email,
            accounts=[
                BankAccountResponse(
                    id=new_account.id,
                    account_type=new_account.account_type,
                    balance=new_account.balance,
                    iban=new_account.iban,
                    created_at=new_account.created_at,
                    transactions=[
                        TransactionResponse(
                            id=initial_transaction.id,
                            amount=initial_transaction.amount,
                            type=initial_transaction.type,
                            created_at=initial_transaction.created_at
                        )
                    ]
                )
            ]
        )
        
    except HTTPException as http_error:
        print(f"Erreur HTTP: {http_error.detail}")
        session.rollback()
        raise http_error
    except Exception as e:
        print(f"Erreur inattendue: {str(e)}")
        print(f"Type d'erreur: {type(e)}")
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

@app.get("/users", response_model=List[UserResponse])
def list_users(session: Session = Depends(get_session)):
    try:
        # Charger les utilisateurs avec leurs comptes
        users = session.query(User).all()
        
        user_responses = []
        for user in users:
            # Préparer la réponse pour chaque utilisateur
            account_responses = []
            if user.account:
                # Charger les transactions si le compte existe
                transactions = (
                    session.query(Transaction)
                    .filter(Transaction.account_id == user.account.id)
                    .order_by(Transaction.created_at.desc())
                    .all()
                )
                
                enriched_transactions = get_enriched_transactions(session, transactions, user.email)
                
                account_responses.append(
                    BankAccountResponse(
                        id=user.account.id,
                        account_type=user.account.account_type,
                        balance=user.account.balance,
                        iban=user.account.iban,
                        created_at=user.account.created_at,
                        transactions=enriched_transactions
                    )
                )
            
            user_responses.append(
                UserResponse(
                    id=user.id,
                    email=user.email,
                    accounts=account_responses
                )
            )
        
        return user_responses
        
    except Exception as e:
        print(f"Erreur détaillée lors de la récupération des utilisateurs: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de la récupération des utilisateurs: {str(e)}"
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
        account = session.query(BankAccount).filter(
            BankAccount.id == account_id,
            BankAccount.user_id == current_user.id
        ).first()
        
        # Vérifier que le compte n'est pas clôturé
        await check_account_not_closed(account)
        
        # Créer la transaction
        new_transaction = Transaction(
            amount=transaction.amount,
            type="deposit",
            account_id=account.id
        )
        session.add(new_transaction)
        
        # Mettre à jour le solde
        account.balance += transaction.amount
        
        session.commit()
        session.refresh(account)
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
                )
            ]  # Removed the for loop here since we only have one account
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
        cancel_until = now + timedelta(seconds=5)
        
        # Créer les transactions
        debit_transaction = Transaction(
            amount=transfer.amount,
            type="transfer_sent",
            account_id=source_account.id,
            created_at=now,
            can_cancel_until=cancel_until
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
        
        # Lier les transactions
        credit_transaction.related_transaction_id = debit_transaction.id
        session.commit()
        
        # Vérifier que les comptes ne sont pas clôturés
        await check_account_not_closed(source_account)
        await check_account_not_closed(recipient_account)
        
        return [
            TransactionResponse(
                id=debit_transaction.id,
                amount=debit_transaction.amount,
                type=debit_transaction.type,
                created_at=debit_transaction.created_at,
                can_cancel_until=debit_transaction.can_cancel_until
            ),
            TransactionResponse(
                id=credit_transaction.id,
                amount=credit_transaction.amount,
                type=credit_transaction.type,
                created_at=credit_transaction.created_at
            )
        ]
        
    except HTTPException:
        session.rollback()
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors du transfert: {str(e)}"
        )

@app.post("/cancel-transfer/{transaction_id}", response_model=List[TransactionResponse])
async def cancel_transfer(
    transaction_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    try:
        # Récupérer la transaction originale
        transaction = (
            session.query(Transaction)
            .join(BankAccount)
            .filter(
                Transaction.id == transaction_id,
                Transaction.type == "transfer_sent",
                BankAccount.user_id == current_user.id
            )
            .first()
        )

        if not transaction:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Transaction non trouvée ou vous n'êtes pas autorisé à l'annuler"
            )

        # Vérifier le délai d'annulation
        now = datetime.utcnow()
        if not transaction.can_cancel_until or now > transaction.can_cancel_until:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Le délai d'annulation est dépassé"
            )

        # Récupérer la transaction liée
        related_transaction = (
            session.query(Transaction)
            .filter(Transaction.related_transaction_id == transaction.id)
            .first()
        )

        if not related_transaction:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Transaction liée non trouvée"
            )

        # Récupérer les comptes
        source_account = (
            session.query(BankAccount)
            .filter(BankAccount.id == transaction.account_id)
            .first()
        )

        destination_account = (
            session.query(BankAccount)
            .filter(BankAccount.id == related_transaction.account_id)
            .first()
        )

        # Vérifier les fonds
        if destination_account.balance < transaction.amount:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Le destinataire n'a plus les fonds suffisants"
            )

        # Créer les transactions d'annulation
        cancellation_sent = Transaction(
            amount=transaction.amount,
            type="cancellation_sent",
            account_id=destination_account.id,
            created_at=now,
            related_transaction_id=transaction.id
        )

        cancellation_received = Transaction(
            amount=transaction.amount,
            type="cancellation_received",
            account_id=source_account.id,
            created_at=now,
            related_transaction_id=transaction.id
        )

        # Mettre à jour les soldes
        source_account.balance += transaction.amount
        destination_account.balance -= transaction.amount

        # Désactiver l'annulation
        transaction.can_cancel_until = None

        # Sauvegarder
        session.add(cancellation_sent)
        session.add(cancellation_received)
        session.commit()

        return [
            TransactionResponse(
                id=cancellation_sent.id,
                amount=cancellation_sent.amount,
                type=cancellation_sent.type,
                created_at=cancellation_sent.created_at
            ),
            TransactionResponse(
                id=cancellation_received.id,
                amount=cancellation_received.amount,
                type=cancellation_received.type,
                created_at=cancellation_received.created_at
            )
        ]

    except HTTPException:
        session.rollback()
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'annulation: {str(e)}"
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

@app.delete("/account/{account_id}/close", response_model=UserResponse)
async def close_account(
    account_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    try:
        # Récupérer le compte à clôturer
        account_to_close = (
            session.query(BankAccount)
            .filter(
                BankAccount.id == account_id,
                BankAccount.user_id == current_user.id
            )
            .first()
        )

        if not account_to_close:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Compte non trouvé"
            )

        # Vérifier que ce n'est pas le compte principal
        if account_to_close.account_type == "principal":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Le compte principal ne peut pas être clôturé"
            )

        # Vérifier si le compte n'est pas déjà clôturé
        if account_to_close.closed_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Ce compte est déjà clôturé"
            )

        # Vérifier s'il y a des transactions en cours (non finalisées)
        pending_transactions = (
            session.query(Transaction)
            .filter(
                Transaction.account_id == account_id,
                Transaction.can_cancel_until != None  # Transactions qui peuvent encore être annulées
            )
            .first()
        )

        if pending_transactions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Ce compte a des transactions en cours et ne peut pas être clôturé"
            )

        # Récupérer le compte principal
        main_account = (
            session.query(BankAccount)
            .filter(
                BankAccount.user_id == current_user.id,
                BankAccount.account_type == "principal"
            )
            .first()
        )

        if not main_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Compte principal non trouvé"
            )

        # Transférer le solde vers le compte principal
        if account_to_close.balance > 0:
            now = datetime.utcnow()
            
            # Créer les transactions de transfert
            withdrawal = Transaction(
                amount=account_to_close.balance,
                type="account_closure_withdrawal",
                account_id=account_to_close.id,
                created_at=now
            )
            
            deposit = Transaction(
                amount=account_to_close.balance,
                type="account_closure_deposit",
                account_id=main_account.id,
                created_at=now
            )
            
            # Mettre à jour les soldes
            main_account.balance += account_to_close.balance
            account_to_close.balance = Decimal("0.00")
            
            session.add(withdrawal)
            session.add(deposit)

        # Marquer le compte comme clôturé
        account_to_close.closed_at = datetime.utcnow()
        
        session.commit()

        # Récupérer les transactions du compte principal pour la réponse
        transactions = (
            session.query(Transaction)
            .filter(Transaction.account_id == main_account.id)
            .order_by(Transaction.created_at.desc())
            .all()
        )

        enriched_transactions = get_enriched_transactions(session, transactions, current_user.email)

        return UserResponse(
            id=current_user.id,
            email=current_user.email,
            accounts=[
                BankAccountResponse(
                    id=main_account.id,
                    account_type=main_account.account_type,
                    balance=main_account.balance,
                    iban=main_account.iban,
                    created_at=main_account.created_at,
                    transactions=enriched_transactions
                )
            ]
        )

    except HTTPException:
        session.rollback()
        raise
    except Exception as e:
        session.rollback()
        print(f"Erreur lors de la clôture du compte: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de la clôture du compte: {str(e)}"
        )

@app.post("/beneficiaries", response_model=BeneficiaryResponse)
async def add_beneficiary(
    beneficiary: BeneficiaryCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    try:
        # Vérifier que le bénéficiaire n'est pas un compte de l'utilisateur
        user_accounts = session.query(BankAccount).filter(
            BankAccount.user_id == current_user.id
        ).all()
        
        if any(account.iban == beneficiary.iban for account in user_accounts):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Vous ne pouvez pas ajouter votre propre compte comme bénéficiaire"
            )
        
        # Vérifier que le compte du bénéficiaire existe
        beneficiary_account = session.query(BankAccount).filter(
            BankAccount.iban == beneficiary.iban
        ).first()
        
        if not beneficiary_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Le compte bénéficiaire n'existe pas"
            )
        
        # Vérifier que le bénéficiaire n'est pas déjà ajouté
        existing_beneficiary = session.query(Beneficiary).filter(
            Beneficiary.user_id == current_user.id,
            Beneficiary.iban == beneficiary.iban
        ).first()
        
        if existing_beneficiary:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Ce bénéficiaire est déjà dans votre liste"
            )
        
        # Créer le bénéficiaire
        new_beneficiary = Beneficiary(
            name=beneficiary.name,
            iban=beneficiary.iban,
            user_id=current_user.id
        )
        
        session.add(new_beneficiary)
        session.commit()
        session.refresh(new_beneficiary)
        
        return BeneficiaryResponse(
            id=new_beneficiary.id,
            name=new_beneficiary.name,
            iban=new_beneficiary.iban,
            created_at=new_beneficiary.created_at
        )
        
    except HTTPException:
        session.rollback()
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'ajout du bénéficiaire: {str(e)}"
        )

@app.get("/beneficiaries", response_model=List[BeneficiaryResponse])
async def list_beneficiaries(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    try:
        beneficiaries = session.query(Beneficiary).filter(
            Beneficiary.user_id == current_user.id
        ).order_by(Beneficiary.name).all()
        
        return [
            BeneficiaryResponse(
                id=b.id,
                name=b.name,
                iban=b.iban,
                created_at=b.created_at
            ) for b in beneficiaries
        ]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de la récupération des bénéficiaires: {str(e)}"
        )

@app.delete("/beneficiaries/{beneficiary_id}")
async def delete_beneficiary(
    beneficiary_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    try:
        beneficiary = session.query(Beneficiary).filter(
            Beneficiary.id == beneficiary_id,
            Beneficiary.user_id == current_user.id
        ).first()
        
        if not beneficiary:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Bénéficiaire non trouvé"
            )
        
        session.delete(beneficiary)
        session.commit()
        
        return {"message": "Bénéficiaire supprimé avec succès"}
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de la suppression du bénéficiaire: {str(e)}"
        )

async def check_account_not_closed(account: BankAccount):
    if account.closed_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ce compte est clôturé et ne peut plus être utilisé pour des transactions"
        )