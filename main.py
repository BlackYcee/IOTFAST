from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.sql import func
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- CONFIGURACIÓN DE SEGURIDAD ---
SECRET_KEY = "TU_SECRETO_SUPER_SEGURO_CAMBIALO" # En prod usa una variable de entorno
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- BASE DE DATOS ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./condominio.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI(title="Sistema IoT Condominio - Secure")

# ==========================================
# 1. MODELOS BD
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
    email = Column(String, unique=True, index=True)
    nombre = Column(String)
    hashed_password = Column(String)
    rol = Column(String, default="OPERADOR") # ADMINISTRADOR / OPERADOR
    estado = Column(String, default="ACTIVO")
    id_departamento = Column(Integer, ForeignKey("departamentos.id_departamento"))
    departamento = relationship("DepartamentoDB", back_populates="usuarios")

class SensorDB(Base):
    __tablename__ = "sensores"
    id_sensor = Column(Integer, primary_key=True, index=True)
    codigo_sensor = Column(String, unique=True, index=True)
    estado = Column(String, default="ACTIVO")
    tipo = Column(String) 
    id_departamento = Column(Integer, ForeignKey("departamentos.id_departamento"))
    departamento = relationship("DepartamentoDB", back_populates="sensores")

class EventoAccesoDB(Base):
    __tablename__ = "eventos_acceso"
    id_evento = Column(Integer, primary_key=True, index=True)
    tipo_evento = Column(String) 
    fecha_hora = Column(DateTime, default=func.now())
    resultado = Column(String)
    usuario_nombre = Column(String, nullable=True) # Guardamos nombre por facilidad histórica

# Tabla para comandos pendientes hacia el ESP32
class ComandoPendienteDB(Base):
    __tablename__ = "comandos_pendientes"
    id_comando = Column(Integer, primary_key=True, index=True)
    destino = Column(String) # Puede ser id_departamento o MAC del ESP
    accion = Column(String)  # ABRIR
    procesado = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

# ==========================================
# 2. UTILIDADES DE AUTH
# ==========================================
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(UsuarioDB).filter(UsuarioDB.email == email).first()
    if user is None: raise credentials_exception
    return user

# ==========================================
# 3. SCHEMAS (Pydantic)
# ==========================================
class Token(BaseModel):
    access_token: str
    token_type: str
    rol: str
    nombre: str
    id_departamento: int

class SensorCreate(BaseModel):
    codigo: str
    tipo: str

class SensorUpdate(BaseModel):
    estado: str

class BarreraCmd(BaseModel):
    accion: str # ABRIR

# ==========================================
# 4. ENDPOINTS
# ==========================================

# --- A. LOGIN (Para la App) ---
@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UsuarioDB).filter(UsuarioDB.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.email})
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "rol": user.rol,
        "nombre": user.nombre,
        "id_departamento": user.id_departamento
    }

# --- B. GESTIÓN DE SENSORES (Solo Admin) ---
@app.post("/api/sensores", status_code=201)
def crear_sensor(sensor: SensorCreate, 
                 current_user: UsuarioDB = Depends(get_current_user), 
                 db: Session = Depends(get_db)):
    
    if current_user.rol != "ADMINISTRADOR":
        raise HTTPException(status_code=403, detail="No autorizado")

    db_sensor = SensorDB(
        codigo_sensor=sensor.codigo, 
        tipo=sensor.tipo,
        id_departamento=current_user.id_departamento
    )
    db.add(db_sensor)
    db.commit()
    return {"msg": "Sensor creado"}

@app.get("/api/sensores")
def listar_sensores(current_user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    # Solo ve sensores de SU departamento
    return db.query(SensorDB).filter(SensorDB.id_departamento == current_user.id_departamento).all()

@app.put("/api/sensores/{codigo_sensor}")
def actualizar_estado(codigo_sensor: str, estado: SensorUpdate, 
                      current_user: UsuarioDB = Depends(get_current_user), 
                      db: Session = Depends(get_db)):
    if current_user.rol != "ADMINISTRADOR":
        raise HTTPException(status_code=403, detail="No autorizado")
    
    sensor = db.query(SensorDB).filter(SensorDB.codigo_sensor == codigo_sensor).first()
    if not sensor: raise HTTPException(404, "Sensor no encontrado")
    
    sensor.estado = estado.estado
    db.commit()
    return {"msg": "Estado actualizado"}

# --- C. CONTROL DE BARRERA (App -> Server -> ESP32) ---

# 1. La App manda la orden
@app.post("/api/barrera/comando")
def enviar_comando_barrera(cmd: BarreraCmd, 
                           current_user: UsuarioDB = Depends(get_current_user), 
                           db: Session = Depends(get_db)):
    
    # Registrar evento
    evento = EventoAccesoDB(
        tipo_evento="APP_MANUAL",
        resultado="PERMITIDO",
        usuario_nombre=current_user.nombre
    )
    db.add(evento)
    
    # Encolar comando para el ESP32 (asociado al depto)
    nuevo_cmd = ComandoPendienteDB(
        destino=str(current_user.id_departamento), # O usa un identificador fijo si hay 1 sola barrera
        accion="ABRIR",
        procesado=False
    )
    db.add(nuevo_cmd)
    db.commit()
    return {"msg": "Comando enviado a la barrera"}

# 2. El ESP32 pregunta si hay órdenes (Polling)
@app.get("/api/esp32/comandos")
def verificar_comandos_pendientes(db: Session = Depends(get_db)):
    # Busca comandos no procesados. 
    # Para simplificar, si encuentra CUALQUIERA sin procesar, devuelve abrir.
    cmd = db.query(ComandoPendienteDB).filter(ComandoPendienteDB.procesado == False).first()
    
    if cmd:
        cmd.procesado = True # Marcar como leído
        db.commit()
        return {"accion": "ABRIR"}
    
    return {"accion": "NADA"}

# 3. El ESP32 valida acceso RFID
class ValidacionRequest(BaseModel):
    uid: str

@app.post("/api/esp32/validar")
def validar_rfid(req: ValidacionRequest, db: Session = Depends(get_db)):
    sensor = db.query(SensorDB).filter(SensorDB.codigo_sensor == req.uid).first()
    
    evt = EventoAccesoDB(tipo_evento="RFID_INTENTO", usuario_nombre="Desconocido")
    
    if not sensor:
        evt.resultado = "DENEGADO_DESCONOCIDO"
        db.add(evt); db.commit()
        return {"acceso": False}
    
    evt.usuario_nombre = f"Depto {sensor.id_departamento}"
    
    if sensor.estado != "ACTIVO":
        evt.resultado = f"DENEGADO_{sensor.estado}"
        db.add(evt); db.commit()
        return {"acceso": False}
    
    # Validar usuario dueño del sensor (Opcional, se puede expandir)
    
    evt.resultado = "PERMITIDO"
    db.add(evt); db.commit()
    return {"acceso": True}

# --- D. HISTORIAL ---
@app.get("/api/historial")
def ver_historial(current_user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(EventoAccesoDB).order_by(EventoAccesoDB.fecha_hora.desc()).limit(30).all()

# --- SETUP INICIAL ---
@app.post("/setup")
def setup_inicial(db: Session = Depends(get_db)):
    if not db.query(UsuarioDB).first():
        depto = DepartamentoDB(numero="101")
        db.add(depto)
        db.commit()
        db.refresh(depto)
        
        # Admin: pass = admin123
        hashed = get_password_hash("admin123")
        admin = UsuarioDB(email="admin@test.com", nombre="Admin Jefe", hashed_password=hashed, rol="ADMINISTRADOR", id_departamento=depto.id_departamento)
        
        # Operador: pass = user123
        hashed_op = get_password_hash("user123")
        user = UsuarioDB(email="user@test.com", nombre="Vecino Juan", hashed_password=hashed_op, rol="OPERADOR", id_departamento=depto.id_departamento)
        
        db.add(admin)
        db.add(user)
        db.commit()
        return {"msg": "Usuarios creados: admin@test.com / user@test.com"}
    return {"msg": "Ya existen datos"}