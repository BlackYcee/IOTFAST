from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import sessionmaker, Session, relationship, declarative_base
from sqlalchemy.sql import func
from passlib.context import CryptContext
from jose import JWTError, jwt
import bcrypt

# ==========================================
# 1. CONFIGURACIÓN Y PARCHES
# ==========================================

# Parche para compatibilidad de bcrypt
if not hasattr(bcrypt, "__about__"):
    bcrypt.__about__ = type('About', (object,), {'__version__': bcrypt.__version__})

SECRET_KEY = "TI3V42_LA_SERENA_SECRET"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ==========================================
# 2. CONFIGURACIÓN DE BASE DE DATOS
# ==========================================

DATABASE_URL = "sqlite:///./condominio_final.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==========================================
# 3. MODELOS DE BASE DE DATOS (SQLAlchemy)
# ==========================================

class DepartamentoDB(Base):
    __tablename__ = "departamentos"
    id_departamento = Column(Integer, primary_key=True, index=True)
    numero = Column(String)
    
    usuarios = relationship("UsuarioDB", back_populates="departamento")
    sensores = relationship("SensorDB", back_populates="departamento")

class UsuarioDB(Base):
    __tablename__ = "usuarios"
    id_usuario = Column(Integer, primary_key=True, index=True)
    nombre = Column(String)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    rol = Column(String)  # ADMINISTRADOR / OPERADOR
    id_departamento = Column(Integer, ForeignKey("departamentos.id_departamento"))
    
    departamento = relationship("DepartamentoDB", back_populates="usuarios")
    eventos = relationship("EventoAccesoDB", back_populates="usuario")

class SensorDB(Base):
    __tablename__ = "sensores"
    id_sensor = Column(Integer, primary_key=True, index=True)
    codigo_sensor = Column(String, unique=True)
    tipo = Column(String)  # Llavero / Tarjeta
    activo = Column(Boolean, default=True)
    id_departamento = Column(Integer, ForeignKey("departamentos.id_departamento"))
    id_usuario = Column(Integer, ForeignKey("usuarios.id_usuario"))
    
    departamento = relationship("DepartamentoDB", back_populates="sensores")
    usuario = relationship("UsuarioDB")

class EventoAccesoDB(Base):
    __tablename__ = "eventos_acceso"
    id_evento = Column(Integer, primary_key=True, index=True)
    tipo_evento = Column(String)
    resultado = Column(String)  # PERMITIDO / DENEGADO
    fecha_hora = Column(DateTime, default=func.now())
    id_usuario = Column(Integer, ForeignKey("usuarios.id_usuario"))
    id_departamento = Column(Integer)
    
    usuario = relationship("UsuarioDB", back_populates="eventos")

# Crear tablas
Base.metadata.create_all(bind=engine)

# ==========================================
# 4. ESQUEMAS DE DATOS (Pydantic)
# ==========================================

class UserBase(BaseModel):
    nombre: str
    email: str
    rol: str
    id_departamento: int

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id_usuario: int
    class Config: from_attributes = True

class SensorCreate(BaseModel):
    codigo_sensor: str
    tipo: str
    id_usuario: int

class SensorResponse(BaseModel):
    id_sensor: int
    codigo_sensor: str
    activo: bool
    tipo: str
    class Config: from_attributes = True

class EventoResponse(BaseModel):
    id_evento: int
    tipo_evento: str
    resultado: str
    fecha_hora: datetime
    id_usuario: int
    class Config: from_attributes = True

# ==========================================
# 5. DEPENDENCIAS
# ==========================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="No se pudo validar credenciales"
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = db.query(UsuarioDB).filter(UsuarioDB.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# ==========================================
# 6. INICIALIZACIÓN DE APP Y ENDPOINTS
# ==========================================

app = FastAPI(title="Control de Acceso IoT")

# --- Autenticación ---

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UsuarioDB).filter(UsuarioDB.email == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Email o contraseña incorrectos")
    
    token = jwt.encode({"sub": user.email}, SECRET_KEY, algorithm=ALGORITHM)
    return {
        "access_token": token, 
        "token_type": "bearer", 
        "rol": user.rol, 
        "user_id": user.id_usuario
    }

# --- CRUD Usuarios (Sólo ADMIN) ---

@app.post("/api/usuarios", response_model=UserResponse)
def crear_usuario(user_data: UserCreate, current_admin: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_admin.rol != "ADMINISTRADOR":
        raise HTTPException(status_code=403, detail="No tienes permisos")
    
    hashed_pw = pwd_context.hash(user_data.password)
    nuevo_usuario = UsuarioDB(
        nombre=user_data.nombre,
        email=user_data.email,
        password_hash=hashed_pw,
        rol=user_data.rol,
        id_departamento=user_data.id_departamento
    )
    db.add(nuevo_usuario)
    db.commit()
    db.refresh(nuevo_usuario)
    return nuevo_usuario

@app.get("/api/usuarios", response_model=List[UserResponse])
def listar_usuarios(current_admin: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(UsuarioDB).all()

@app.delete("/api/usuarios/{id_usuario}")
def eliminar_usuario(id_usuario: int, current_admin: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_admin.rol != "ADMINISTRADOR":
        raise HTTPException(status_code=403)
    user = db.query(UsuarioDB).filter(UsuarioDB.id_usuario == id_usuario).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    db.delete(user)
    db.commit()
    return {"msg": "Usuario eliminado"}

# --- Gestión de Sensores ---

@app.post("/api/sensores", response_model=SensorResponse)
def registrar_sensor(data: SensorCreate, user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.rol != "ADMINISTRADOR":
        raise HTTPException(status_code=403)
    nuevo = SensorDB(**data.model_dump(), id_departamento=user.id_departamento, activo=True)
    db.add(nuevo)
    db.commit()
    db.refresh(nuevo)
    return nuevo

@app.get("/api/sensores", response_model=List[SensorResponse])
def listar_sensores(current_admin: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_admin.rol != "ADMINISTRADOR":
        raise HTTPException(status_code=403)
    return db.query(SensorDB).all()
    
@app.patch("/api/sensores/{id_sensor}/toggle")
def alternar_estado_sensor(id_sensor: int, current_admin: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_admin.rol != "ADMINISTRADOR":
        raise HTTPException(status_code=403)
    sensor = db.query(SensorDB).filter(SensorDB.id_sensor == id_sensor).first()
    if not sensor:
        raise HTTPException(status_code=404)
    sensor.activo = not sensor.activo
    db.commit()
    return {"msg": f"Sensor {'activado' if sensor.activo else 'desactivado'}", "activo": sensor.activo}

# --- Auditoría y Eventos ---

@app.get("/api/usuarios/{id_usuario}/historial", response_model=List[EventoResponse])
def historial_por_usuario(id_usuario: int, db: Session = Depends(get_db), current_user: UsuarioDB = Depends(get_current_user)):
    if current_user.rol != "ADMINISTRADOR" and current_user.id_usuario != id_usuario:
        raise HTTPException(status_code=403)
    return db.query(EventoAccesoDB).filter(EventoAccesoDB.id_usuario == id_usuario).all()

# --- Endpoint para Dispositivo IoT ---

@app.get("/api/iot/validar")
def validar_rfid(uid: str, db: Session = Depends(get_db)):
    sensor = db.query(SensorDB).filter(SensorDB.codigo_sensor == uid).first()
    if sensor and sensor.activo:
        evento = EventoAccesoDB(
            tipo_evento="RFID_ACCESO",
            resultado="PERMITIDO",
            id_usuario=sensor.id_usuario,
            id_departamento=sensor.id_departamento
        )
        db.add(evento)
        db.commit()
        return {"access": True, "user": sensor.usuario.nombre}
    return {"access": False, "msg": "Denegado o Inactivo"}

# --- Setup Inicial ---

@app.post("/setup")
def setup(db: Session = Depends(get_db)):
    if db.query(DepartamentoDB).first():
        return {"msg": "El sistema ya está configurado"}
    
    dep = DepartamentoDB(numero="101")
    db.add(dep)
    db.commit()
    db.refresh(dep)
    
    admin = UsuarioDB(
        nombre="Admin Jose",
        email="admin@test.com",
        password_hash=pwd_context.hash("123"),
        rol="ADMINISTRADOR",
        id_departamento=dep.id_departamento
    )
    db.add(admin)
    db.commit()
    return {"msg": "Admin creado: admin@test.com / 123"}
#jaja