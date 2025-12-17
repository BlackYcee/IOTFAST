from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.sql import func
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- 1. CONFIGURACIÓN Y SEGURIDAD ---
SECRET_KEY = "PROYECTO_TITULO_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SQLALCHEMY_DATABASE_URL = "sqlite:///./condominio_cloud.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI(title="Control de Acceso API", version="2.0")

# --- 2. MODELOS DE BASE DE DATOS (SQLAlchemy) ---

class DepartamentoDB(Base):
    __tablename__ = "departamentos"
    id = Column(Integer, primary_key=True, index=True)
    numero = Column(String, index=True)
    torre = Column(String, nullable=True)
    usuarios = relationship("UsuarioDB", back_populates="departamento")
    sensores = relationship("SensorDB", back_populates="departamento")

class UsuarioDB(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    nombre = Column(String)
    hashed_password = Column(String)
    rol = Column(String, default="OPERADOR")
    estado = Column(String, default="ACTIVO")
    id_departamento = Column(Integer, ForeignKey("departamentos.id"))
    departamento = relationship("DepartamentoDB", back_populates="usuarios")

class SensorDB(Base):
    __tablename__ = "sensores"
    id = Column(Integer, primary_key=True, index=True)
    codigo_sensor = Column(String, unique=True, index=True)
    estado = Column(String, default="ACTIVO")
    tipo = Column(String)
    id_departamento = Column(Integer, ForeignKey("departamentos.id"))
    departamento = relationship("DepartamentoDB", back_populates="sensores")

class EventoDB(Base):
    __tablename__ = "eventos"
    id = Column(Integer, primary_key=True, index=True)
    fecha_hora = Column(DateTime, default=func.now())
    tipo = Column(String)
    resultado = Column(String)
    descripcion = Column(String)
    id_departamento = Column(Integer, nullable=True)

Base.metadata.create_all(bind=engine)

# --- 3. ESQUEMAS DE DATOS (Pydantic v2 - JSON) ---

class SensorBase(BaseModel):
    codigo: str
    tipo: str

class SensorResponse(SensorBase):
    id: int
    estado: str
    class Config:
        from_attributes = True  # Esto reemplaza orm_mode en Pydantic V2

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    nombre: str
    rol: str

class MsgResponse(BaseModel):
    message: str
    detail: Optional[str] = None

# --- 4. DEPENDENCIAS Y UTILS ---

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    exc = HTTPException(status_code=401, detail="Token inválido")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email: raise exc
    except JWTError: raise exc
    user = db.query(UsuarioDB).filter(UsuarioDB.email == email).first()
    if not user: raise exc
    return user

# --- 5. ENDPOINTS (API REST) ---

@app.post("/setup", tags=["Admin"])
def setup_db(db: Session = Depends(get_db)):
    if db.query(UsuarioDB).first():
        return {"message": "La base de datos ya está inicializada"}
    
    depto = DepartamentoDB(numero="101", torre="A")
    db.add(depto); db.commit(); db.refresh(depto)
    
    admin = UsuarioDB(
        email="admin@condominio.cl", 
        nombre="Admin Jefe", 
        hashed_password=pwd_context.hash("admin123"), 
        rol="ADMINISTRADOR",
        id_departamento=depto.id
    )
    db.add(admin); db.commit()
    return {"message": "Sistema inicializado", "admin": "admin@condominio.cl"}

@app.post("/token", response_model=TokenResponse, tags=["Auth"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UsuarioDB).filter(UsuarioDB.email == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Credenciales incorrectas")
    
    token = jwt.encode({"sub": user.email, "exp": datetime.utcnow() + timedelta(minutes=120)}, SECRET_KEY, algorithm=ALGORITHM)
    return {
        "access_token": token, 
        "token_type": "bearer", 
        "nombre": user.nombre, 
        "rol": user.rol
    }

@app.get("/api/sensores", response_model=List[SensorResponse], tags=["Sensores"])
def listar_sensores(user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(SensorDB).filter(SensorDB.id_departamento == user.id_departamento).all()

@app.post("/api/sensores", response_model=SensorResponse, tags=["Sensores"])
def crear_sensor(data: SensorBase, user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.rol != "ADMINISTRADOR":
        raise HTTPException(status_code=403, detail="No tienes permisos")
    
    nuevo = SensorDB(codigo_sensor=data.codigo, tipo=data.tipo, id_departamento=user.id_departamento)
    db.add(nuevo); db.commit(); db.refresh(nuevo)
    return nuevo

@app.post("/api/simulacion/validar", tags=["IoT"])
def validar_rfid(uid: str, db: Session = Depends(get_db)):
    sensor = db.query(SensorDB).filter(SensorDB.codigo_sensor == uid).first()
    if not sensor or sensor.estado != "ACTIVO":
        return {"acceso": False, "led": "ROJO", "msg": "Denegado"}
    
    # Registrar evento
    nuevo_evento = EventoDB(tipo="RFID", resultado="EXITO", descripcion=f"Acceso UID: {uid}", id_departamento=sensor.id_departamento)
    db.add(nuevo_evento); db.commit()
    return {"acceso": True, "led": "VERDE", "accion": "ABRIR_BARRERA"}