from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.sql import func

# --- CONFIGURACIÓN BASE DE DATOS (SQLITE) ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./condominio.db"

# check_same_thread=False es necesario para SQLite en FastAPI
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI(title="Sistema Control de Acceso Condominio IoT")

# ==========================================
# 1. MODELOS DE BASE DE DATOS (TABLAS)
# ==========================================

class DepartamentoDB(Base):
    __tablename__ = "departamentos"
    
    id_departamento = Column(Integer, primary_key=True, index=True)
    numero = Column(String, index=True)  # Ej: "101"
    torre = Column(String)               # Ej: "A"
    otros_datos = Column(String, nullable=True) # Ej: "Piso 1"

    # Relaciones (para facilitar consultas)
    usuarios = relationship("UsuarioDB", back_populates="departamento")
    sensores = relationship("SensorDB", back_populates="departamento")

class UsuarioDB(Base):
    __tablename__ = "usuarios"
    
    id_usuario = Column(Integer, primary_key=True, index=True)
    nombre = Column(String)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String) # En producción usar bcrypt
    estado = Column(String, default="ACTIVO") # ACTIVO / INACTIVO / BLOQUEADO
    rol = Column(String, default="OPERADOR")  # ADMINISTRADOR / OPERADOR
    otros_datos = Column(String, nullable=True) # Teléfono, Rut
    
    # FK necesaria para relacionar usuario con depto
    id_departamento = Column(Integer, ForeignKey("departamentos.id_departamento"))
    
    departamento = relationship("DepartamentoDB", back_populates="usuarios")
    sensores = relationship("SensorDB", back_populates="usuario")

class SensorDB(Base):
    __tablename__ = "sensores"
    
    id_sensor = Column(Integer, primary_key=True, index=True)
    codigo_sensor = Column(String, unique=True, index=True) # UID/MAC
    estado = Column(String, default="ACTIVO") # ACTIVO / INACTIVO / PERDIDO / BLOQUEADO
    tipo = Column(String) # Llavero / Tarjeta
    fecha_alta = Column(DateTime, default=func.now())
    fecha_baja = Column(DateTime, nullable=True)
    
    id_departamento = Column(Integer, ForeignKey("departamentos.id_departamento"))
    # FK opcional para asignar sensor a un usuario específico
    id_usuario = Column(Integer, ForeignKey("usuarios.id_usuario"), nullable=True)

    departamento = relationship("DepartamentoDB", back_populates="sensores")
    usuario = relationship("UsuarioDB", back_populates="sensores")

class EventoAccesoDB(Base):
    __tablename__ = "eventos_acceso"
    
    id_evento = Column(Integer, primary_key=True, index=True)
    tipo_evento = Column(String) 
    # Tipos: ACCESO_VALIDO, ACCESO_RECHAZADO, APERTURA_MANUAL, CIERRE_MANUAL
    fecha_hora = Column(DateTime, default=func.now())
    resultado = Column(String) # PERMITIDO / DENEGADO
    
    # Claves foráneas
    id_sensor = Column(Integer, ForeignKey("sensores.id_sensor"), nullable=True)
    id_usuario = Column(Integer, ForeignKey("usuarios.id_usuario"), nullable=True)

# Crear todas las tablas
Base.metadata.create_all(bind=engine)

# ==========================================
# 2. SCHEMAS PYDANTIC (VALIDACIÓN DE DATOS)
# ==========================================

# Request desde el NodeMCU
class ValidacionRequest(BaseModel):
    uid: str 

# Request desde la App para abrir manual
class AperturaManualRequest(BaseModel):
    id_usuario: int # Quién abrió desde la app

# Request para crear sensores (Admin)
class SensorCreate(BaseModel):
    codigo: str
    tipo: str
    id_departamento: int
    id_usuario: int

# ==========================================
# 3. LÓGICA / ENDPOINTS
# ==========================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def root():
    return {"status": "Sistema Online", "db": "SQLite Configurada"}

# --- ENDPOINT 1: VALIDACIÓN RFID (Para NodeMCU) ---
@app.post("/api/validar-acceso")
def validar_acceso(request: ValidacionRequest, db: Session = Depends(get_db)):
    """
    Recibe el UID de la tarjeta, verifica en BD y registra el evento.
    """
    # 1. Buscar sensor
    sensor = db.query(SensorDB).filter(SensorDB.codigo_sensor == request.uid).first()
    
    nuevo_evento = EventoAccesoDB(
        fecha_hora=datetime.now(),
        tipo_evento="ACCESO_RECHAZADO",
        resultado="DENEGADO"
    )

    if not sensor:
        # Tarjeta desconocida
        nuevo_evento.tipo_evento = "ACCESO_RECHAZADO"
        nuevo_evento.resultado = "DENEGADO"
        db.add(nuevo_evento)
        db.commit()
        return {"acceso": False, "mensaje": "Sensor no registrado"}

    # Asociar datos al evento
    nuevo_evento.id_sensor = sensor.id_sensor
    nuevo_evento.id_usuario = sensor.id_usuario # Si tiene dueño
    
    # 2. Verificar estado
    if sensor.estado == "ACTIVO":
        # Verificar estado del usuario dueño (Opcional pero recomendado)
        usuario_dueno = db.query(UsuarioDB).filter(UsuarioDB.id_usuario == sensor.id_usuario).first()
        if usuario_dueno and usuario_dueno.estado != "ACTIVO":
             nuevo_evento.tipo_evento = "ACCESO_RECHAZADO"
             nuevo_evento.resultado = "DENEGADO_USUARIO_BLOQUEADO"
             db.add(nuevo_evento)
             db.commit()
             return {"acceso": False, "mensaje": "Usuario bloqueado"}

        # ACCESO CONCEDIDO
        nuevo_evento.tipo_evento = "ACCESO_VALIDO"
        nuevo_evento.resultado = "PERMITIDO"
        db.add(nuevo_evento)
        db.commit()
        return {"acceso": True, "mensaje": "Bienvenido"}
    
    else:
        # Sensor inactivo/perdido
        nuevo_evento.tipo_evento = "ACCESO_RECHAZADO"
        nuevo_evento.resultado = f"DENEGADO_SENSOR_{sensor.estado}"
        db.add(nuevo_evento)
        db.commit()
        return {"acceso": False, "mensaje": f"Sensor {sensor.estado}"}

# --- ENDPOINT 2: APERTURA MANUAL DESDE APP ---
@app.post("/api/apertura-manual")
def apertura_manual(req: AperturaManualRequest, db: Session = Depends(get_db)):
    usuario = db.query(UsuarioDB).filter(UsuarioDB.id_usuario == req.id_usuario).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
    evento = EventoAccesoDB(
        id_usuario=usuario.id_usuario,
        tipo_evento="APERTURA_MANUAL",
        resultado="PERMITIDO",
        fecha_hora=datetime.now()
    )
    db.add(evento)
    db.commit()
    
    # Aquí podrías usar MQTT o una variable global para avisar al NodeMCU
    return {"mensaje": "Barrera abierta manualmente", "estado_barrera": "ABIERTA"}

# --- ENDPOINT 3: CREAR DATOS DE PRUEBA (SOLO PARA INICIALIZAR) ---
@app.post("/setup-datos-prueba")
def setup_datos(db: Session = Depends(get_db)):
    # Crear depto
    depto = DepartamentoDB(numero="101", torre="A", otros_datos="Piso 1")
    db.add(depto)
    db.commit()
    db.refresh(depto)
    
    # Crear Usuario Admin
    admin = UsuarioDB(
        nombre="Juan Admin", 
        email="juan@admin.com", 
        password_hash="secret", 
        rol="ADMINISTRADOR",
        id_departamento=depto.id_departamento
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)
    
    # Crear Sensor
    sensor = SensorDB(
        codigo_sensor="A3 BC 12", # EJEMPLO DE MAC
        tipo="Tarjeta",
        id_departamento=depto.id_departamento,
        id_usuario=admin.id_usuario
    )
    db.add(sensor)
    db.commit()
    
    return {"mensaje": "Datos creados: Depto 101, Usuario Juan, Sensor A3 BC 12"}

# --- ENDPOINT 4: VER HISTORIAL ---
@app.get("/api/historial")
def ver_historial(db: Session = Depends(get_db)):
    # Devuelve los últimos 20 eventos
    eventos = db.query(EventoAccesoDB).order_by(EventoAccesoDB.fecha_hora.desc()).limit(20).all()
    return eventos