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
SECRET_KEY = "PROYECTO_TITULO_SECRET_KEY" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120 # Token dura 2 horas para facilitar pruebas

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- BASE DE DATOS (SQLite local para pruebas) ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./condominio_cloud.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI(title="API Control de Acceso - Cloud Logic")

# ==========================================
# 1. MODELOS BD (Estructura Sugerida Refinada)
# ==========================================

class DepartamentoDB(Base):
    __tablename__ = "departamentos"
    id_departamento = Column(Integer, primary_key=True, index=True)
    numero = Column(String) # Ej: "101"
    torre = Column(String, nullable=True) # Ej: "A"
    usuarios = relationship("UsuarioDB", back_populates="departamento")
    sensores = relationship("SensorDB", back_populates="departamento")

class UsuarioDB(Base):
    __tablename__ = "usuarios"
    id_usuario = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    nombre = Column(String)
    hashed_password = Column(String)
    # ROLES: 'ADMINISTRADOR' (Jefe de depto) | 'OPERADOR' (Residente común)
    rol = Column(String, default="OPERADOR") 
    estado = Column(String, default="ACTIVO") # ACTIVO / INACTIVO
    id_departamento = Column(Integer, ForeignKey("departamentos.id_departamento"))
    departamento = relationship("DepartamentoDB", back_populates="usuarios")

class SensorDB(Base):
    __tablename__ = "sensores"
    id_sensor = Column(Integer, primary_key=True, index=True)
    codigo_sensor = Column(String, unique=True, index=True) # MAC o UID de la tarjeta
    # ESTADOS: 'ACTIVO', 'INACTIVO', 'PERDIDO', 'BLOQUEADO'
    estado = Column(String, default="ACTIVO") 
    tipo = Column(String) # 'TARJETA' o 'LLAVERO'
    fecha_alta = Column(DateTime, default=func.now())
    
    id_departamento = Column(Integer, ForeignKey("departamentos.id_departamento"))
    departamento = relationship("DepartamentoDB", back_populates="sensores")

class EventoAccesoDB(Base):
    __tablename__ = "eventos_acceso"
    id_evento = Column(Integer, primary_key=True, index=True)
    fecha_hora = Column(DateTime, default=func.now())
    
    # TIPO: 'RFID_VALIDO', 'RFID_DENEGADO', 'APP_ABRIR', 'APP_CERRAR'
    tipo_evento = Column(String) 
    resultado = Column(String) # PERMITIDO / DENEGADO
    descripcion = Column(String) # Detalles: "Usuario Juan", "Tarjeta Desconocida", etc.
    
    id_departamento = Column(Integer, nullable=True) # Para filtrar historial por depto

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
        detail="No se pudo validar las credenciales",
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
# 3. SCHEMAS (Pydantic para API)
# ==========================================
class Token(BaseModel):
    access_token: str
    token_type: str
    rol: str
    nombre: str
    id_departamento: int

# Para crear sensores desde la App
class SensorCreate(BaseModel):
    codigo: str # UID RFID
    tipo: str   # TARJETA / LLAVERO

# Para cambiar estado (Activar/Desactivar/Perdido)
class SensorUpdate(BaseModel):
    estado: str 

# Para control manual de barrera
class BarreraManual(BaseModel):
    accion: str # "ABRIR" o "CERRAR"

# Para simular el Hardware RFID enviando datos
class SimulacionRFID(BaseModel):
    uid: str

# Salida de historial
class EventoOut(BaseModel):
    fecha_hora: datetime
    tipo_evento: str
    resultado: str
    descripcion: str
    class Config:
        orm_mode = True

# ==========================================
# 4. ENDPOINTS
# ==========================================

# --- A. SETUP & LOGIN ---

@app.post("/setup", tags=["Configuración"])
def inicializar_datos_prueba(db: Session = Depends(get_db)):
    """Crea datos base: Depto 101, 1 Admin y 1 Operador"""
    if db.query(DepartamentoDB).filter_by(numero="101").first():
        return {"msg": "Datos ya existen. Usa /token para loguearte."}

    # 1. Crear Departamento
    depto = DepartamentoDB(numero="101", torre="A")
    db.add(depto)
    db.commit()
    db.refresh(depto)

    # 2. Crear Admin (Jefe de hogar)
    admin = UsuarioDB(
        email="admin@condominio.cl", 
        nombre="Jefe Depto 101", 
        hashed_password=get_password_hash("admin123"), 
        rol="ADMINISTRADOR", 
        id_departamento=depto.id_departamento
    )
    
    # 3. Crear Operador (Hijo/Residente)
    user = UsuarioDB(
        email="hijo@condominio.cl", 
        nombre="Hijo Depto 101", 
        hashed_password=get_password_hash("user123"), 
        rol="OPERADOR", 
        id_departamento=depto.id_departamento
    )

    db.add(admin)
    db.add(user)
    db.commit()
    return {"msg": "Usuarios creados: admin@condominio.cl (pass: admin123) / hijo@condominio.cl (pass: user123)"}

@app.post("/token", response_model=Token, tags=["Auth"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UsuarioDB).filter(UsuarioDB.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Credenciales incorrectas")
    
    if user.estado != "ACTIVO":
        raise HTTPException(status_code=400, detail="Usuario inactivo o bloqueado")

    access_token = create_access_token(data={"sub": user.email})
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "rol": user.rol,
        "nombre": user.nombre,
        "id_departamento": user.id_departamento
    }

# --- B. GESTIÓN DE SENSORES (Req: Solo Admin del Depto) ---

@app.post("/api/sensores", tags=["Sensores"])
def registrar_sensor(sensor: SensorCreate, 
                     current_user: UsuarioDB = Depends(get_current_user), 
                     db: Session = Depends(get_db)):
    
    # VALIDACIÓN DE ROL
    if current_user.rol != "ADMINISTRADOR":
        raise HTTPException(status_code=403, detail="Solo el Administrador del depto puede agregar sensores")

    # Verificar duplicados
    if db.query(SensorDB).filter(SensorDB.codigo_sensor == sensor.codigo).first():
        raise HTTPException(status_code=400, detail="Este código de sensor ya está registrado")

    nuevo_sensor = SensorDB(
        codigo_sensor=sensor.codigo,
        tipo=sensor.tipo,
        estado="ACTIVO",
        id_departamento=current_user.id_departamento
    )
    db.add(nuevo_sensor)
    db.commit()
    return {"msg": "Sensor registrado exitosamente", "codigo": sensor.codigo}

@app.put("/api/sensores/{codigo}/estado", tags=["Sensores"])
def cambiar_estado_sensor(codigo: str, estado_update: SensorUpdate,
                          current_user: UsuarioDB = Depends(get_current_user),
                          db: Session = Depends(get_db)):
    
    if current_user.rol != "ADMINISTRADOR":
        raise HTTPException(status_code=403, detail="Solo el Administrador puede gestionar estados")

    sensor = db.query(SensorDB).filter(
        SensorDB.codigo_sensor == codigo,
        SensorDB.id_departamento == current_user.id_departamento
    ).first()

    if not sensor:
        raise HTTPException(status_code=404, detail="Sensor no encontrado en tu departamento")

    # Estados validos: ACTIVO, INACTIVO, PERDIDO, BLOQUEADO
    sensor.estado = estado_update.estado.upper()
    db.commit()
    return {"msg": f"Sensor {codigo} actualizado a {sensor.estado}"}

@app.get("/api/sensores", tags=["Sensores"])
def listar_mis_sensores(current_user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    """Muestra todos los sensores del departamento del usuario"""
    return db.query(SensorDB).filter(SensorDB.id_departamento == current_user.id_departamento).all()

# --- C. CONTROL MANUAL (APP MÓVIL) ---

@app.post("/api/barrera/manual", tags=["Control Acceso App"])
def control_manual_barrera(cmd: BarreraManual, 
                           current_user: UsuarioDB = Depends(get_current_user), 
                           db: Session = Depends(get_db)):
    """
    La App envía ABRIR o CERRAR.
    Se registra el evento y se asume que la nube notifica al hardware (simulado).
    """
    accion = cmd.accion.upper() # ABRIR o CERRAR
    
    evento = EventoAccesoDB(
        tipo_evento=f"APP_{accion}",
        resultado="PERMITIDO",
        descripcion=f"Acción manual por usuario: {current_user.nombre}",
        id_departamento=current_user.id_departamento
    )
    db.add(evento)
    db.commit()

    return {
        "msg": f"Comando {accion} enviado exitosamente",
        "barrera_estado": "ABIERTA" if accion == "ABRIR" else "CERRADA"
    }

# --- D. SIMULACIÓN HARDWARE (Validador RFID) ---

@app.post("/api/simulacion/validar", tags=["Simulación IoT"])
def validar_acceso_rfid(rfid: SimulacionRFID, db: Session = Depends(get_db)):
    """
    Simula lo que haría el ESP32: Envia el UID leido.
    La API responde si abre o no y registra el evento.
    """
    sensor = db.query(SensorDB).filter(SensorDB.codigo_sensor == rfid.uid).first()
    
    # 1. Caso: Sensor no existe
    if not sensor:
        evt = EventoAccesoDB(
            tipo_evento="RFID_DENEGADO", 
            resultado="DENEGADO", 
            descripcion=f"Intento con tarjeta desconocida: {rfid.uid}",
            id_departamento=None
        )
        db.add(evt); db.commit()
        return {"acceso": False, "mensaje": "Tarjeta no registrada", "led": "ROJO"}

    # 2. Caso: Sensor existe, verificamos estado
    if sensor.estado != "ACTIVO":
        evt = EventoAccesoDB(
            tipo_evento="RFID_DENEGADO",
            resultado="DENEGADO",
            descripcion=f"Sensor {sensor.estado} intentó acceder (Depto {sensor.id_departamento})",
            id_departamento=sensor.id_departamento
        )
        db.add(evt); db.commit()
        return {"acceso": False, "mensaje": f"Tarjeta {sensor.estado}", "led": "ROJO"}

    # 3. Caso: Éxito
    evt = EventoAccesoDB(
        tipo_evento="RFID_VALIDO",
        resultado="PERMITIDO",
        descripcion=f"Entrada autorizada Depto {sensor.id_departamento} ({sensor.tipo})",
        id_departamento=sensor.id_departamento
    )
    db.add(evt); db.commit()
    
    return {
        "acceso": True, 
        "mensaje": "Bienvenido", 
        "led": "VERDE",
        "accion_barrera": "LEVANTAR_Y_BAJAR_10S"
    }

# --- E. HISTORIAL ---

@app.get("/api/historial", response_model=List[EventoOut], tags=["Historial"])
def ver_historial(current_user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Muestra el historial. 
    - Si es Admin, podría ver todo (opcional).
    - Aquí configurado para ver SOLO eventos de SU departamento.
    """
    return db.query(EventoAccesoDB)\
             .filter(EventoAccesoDB.id_departamento == current_user.id_departamento)\
             .order_by(EventoAccesoDB.fecha_hora.desc())\
             .limit(50)\
             .all()