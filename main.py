from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.sql import func

# --- CONFIGURACIÓN BASE DE DATOS ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./condominio.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI(title="Sistema Control de Acceso Condominio IoT")

# ==========================================
# 1. MODELOS DE BASE DE DATOS
# ==========================================

class DepartamentoDB(Base):
    __tablename__ = "departamentos"
    id_departamento = Column(Integer, primary_key=True, index=True)
    numero = Column(String, index=True)
    torre = Column(String)
    otros_datos = Column(String, nullable=True)
    usuarios = relationship("UsuarioDB", back_populates="departamento")
    sensores = relationship("SensorDB", back_populates="departamento")

class UsuarioDB(Base):
    __tablename__ = "usuarios"
    id_usuario = Column(Integer, primary_key=True, index=True)
    nombre = Column(String)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    estado = Column(String, default="ACTIVO") 
    rol = Column(String, default="OPERADOR") # ADMINISTRADOR / OPERADOR
    id_departamento = Column(Integer, ForeignKey("departamentos.id_departamento"))
    departamento = relationship("DepartamentoDB", back_populates="usuarios")
    sensores = relationship("SensorDB", back_populates="usuario")

class SensorDB(Base):
    __tablename__ = "sensores"
    id_sensor = Column(Integer, primary_key=True, index=True)
    codigo_sensor = Column(String, unique=True, index=True) # MAC/UID
    estado = Column(String, default="ACTIVO") # ACTIVO / INACTIVO / PERDIDO
    tipo = Column(String) # Tarjeta / Llavero
    fecha_alta = Column(DateTime, default=func.now())
    id_departamento = Column(Integer, ForeignKey("departamentos.id_departamento"))
    id_usuario = Column(Integer, ForeignKey("usuarios.id_usuario"), nullable=True)
    departamento = relationship("DepartamentoDB", back_populates="sensores")
    usuario = relationship("UsuarioDB", back_populates="sensores")

class EventoAccesoDB(Base):
    __tablename__ = "eventos_acceso"
    id_evento = Column(Integer, primary_key=True, index=True)
    tipo_evento = Column(String) 
    fecha_hora = Column(DateTime, default=func.now())
    resultado = Column(String) # PERMITIDO / DENEGADO
    id_sensor = Column(Integer, ForeignKey("sensores.id_sensor"), nullable=True)
    id_usuario = Column(Integer, ForeignKey("usuarios.id_usuario"), nullable=True)

Base.metadata.create_all(bind=engine)

# ==========================================
# 2. SCHEMAS PYDANTIC (Requests)
# ==========================================

class ValidacionRequest(BaseModel):
    uid: str 

class SensorCreateRequest(BaseModel):
    admin_id: int # ID del admin que hace la operacion
    codigo_sensor: str
    tipo: str # Tarjeta / Llavero
    id_usuario_asignado: int # A quien pertenece el sensor

class SensorEstadoRequest(BaseModel):
    admin_id: int
    nuevo_estado: str # ACTIVO / INACTIVO / PERDIDO

class BarreraManualRequest(BaseModel):
    id_usuario: int
    accion: str # ABRIR / CERRAR

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==========================================
# 3. ENDPOINTS DE NEGOCIO
# ==========================================

@app.get("/")
def root():
    return {"status": "Sistema Online", "version": "1.0.0"}

# --- A. VALIDACIÓN ACCESO (NodeMCU) ---
@app.post("/api/validar-acceso")
def validar_acceso(req: ValidacionRequest, db: Session = Depends(get_db)):
    # 1. Buscar sensor
    sensor = db.query(SensorDB).filter(SensorDB.codigo_sensor == req.uid).first()
    
    nuevo_evento = EventoAccesoDB(
        fecha_hora=datetime.now(),
        tipo_evento="ACCESO_RFID",
        resultado="DENEGADO"
    )

    if not sensor:
        nuevo_evento.resultado = "DENEGADO_SENSOR_NO_REGISTRADO"
        db.add(nuevo_evento)
        db.commit()
        return {"acceso": False, "mensaje": "Sensor No Registrado"}

    nuevo_evento.id_sensor = sensor.id_sensor
    nuevo_evento.id_usuario = sensor.id_usuario

    # 2. Validar Estado del Sensor
    if sensor.estado != "ACTIVO":
        nuevo_evento.resultado = f"DENEGADO_SENSOR_{sensor.estado}"
        db.add(nuevo_evento)
        db.commit()
        return {"acceso": False, "mensaje": f"Sensor {sensor.estado}"}

    # 3. Validar Estado del Usuario Dueño
    usuario = db.query(UsuarioDB).filter(UsuarioDB.id_usuario == sensor.id_usuario).first()
    if usuario and usuario.estado != "ACTIVO":
        nuevo_evento.resultado = "DENEGADO_USUARIO_BLOQUEADO"
        db.add(nuevo_evento)
        db.commit()
        return {"acceso": False, "mensaje": "Usuario Bloqueado"}

    # 4. Acceso Permitido
    nuevo_evento.resultado = "PERMITIDO"
    nuevo_evento.tipo_evento = "ACCESO_VALIDO"
    db.add(nuevo_evento)
    db.commit()
    return {"acceso": True, "mensaje": "Bienvenido"}

# --- B. GESTIÓN DE SENSORES (APP - Solo Admin) ---
@app.post("/api/sensores/crear")
def registrar_sensor(req: SensorCreateRequest, db: Session = Depends(get_db)):
    # Verificar si quien pide es admin
    admin = db.query(UsuarioDB).filter(UsuarioDB.id_usuario == req.admin_id).first()
    if not admin or admin.rol != "ADMINISTRADOR":
        raise HTTPException(status_code=403, detail="No tiene permisos de Administrador")

    # Verificar existencia del sensor
    if db.query(SensorDB).filter(SensorDB.codigo_sensor == req.codigo_sensor).first():
        raise HTTPException(status_code=400, detail="El sensor ya existe")

    # Crear sensor asociado al departamento del Admin
    nuevo_sensor = SensorDB(
        codigo_sensor=req.codigo_sensor,
        tipo=req.tipo,
        id_departamento=admin.id_departamento, # Se asocia al depto del admin
        id_usuario=req.id_usuario_asignado,
        estado="ACTIVO"
    )
    db.add(nuevo_sensor)
    db.commit()
    return {"mensaje": "Sensor registrado exitosamente"}

@app.put("/api/sensores/{codigo}/estado")
def cambiar_estado_sensor(codigo: str, req: SensorEstadoRequest, db: Session = Depends(get_db)):
    # Verificar admin
    admin = db.query(UsuarioDB).filter(UsuarioDB.id_usuario == req.admin_id).first()
    if not admin or admin.rol != "ADMINISTRADOR":
        raise HTTPException(status_code=403, detail="Requiere Rol Administrador")

    sensor = db.query(SensorDB).filter(SensorDB.codigo_sensor == codigo).first()
    if not sensor:
        raise HTTPException(status_code=404, detail="Sensor no encontrado")

    # Validar que el sensor pertenezca al mismo departamento del admin
    if sensor.id_departamento != admin.id_departamento:
        raise HTTPException(status_code=403, detail="No puede gestionar sensores de otro departamento")

    sensor.estado = req.nuevo_estado
    db.commit()
    return {"mensaje": f"Estado actualizado a {req.nuevo_estado}"}

# --- C. CONTROL MANUAL BARRERA (APP) ---
@app.post("/api/barrera/control")
def control_barrera(req: BarreraManualRequest, db: Session = Depends(get_db)):
    usuario = db.query(UsuarioDB).filter(UsuarioDB.id_usuario == req.id_usuario).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario desconocido")

    # Registramos el evento
    evento = EventoAccesoDB(
        id_usuario=usuario.id_usuario,
        tipo_evento=f"MANUAL_{req.accion}", # APERTURA_MANUAL o CIERRE_MANUAL
        resultado="PERMITIDO",
        fecha_hora=datetime.now()
    )
    db.add(evento)
    db.commit()

    # Logica de respuesta para la App (que luego notificará al NodeMCU via MQTT o polling)
    return {"estado_barrera": "ABIERTA" if req.accion == "ABRIR" else "CERRADA", "mensaje": "Comando enviado"}

# --- D. HISTORIAL Y DATOS ---
@app.get("/api/historial")
def ver_historial(db: Session = Depends(get_db)):
    return db.query(EventoAccesoDB).order_by(EventoAccesoDB.fecha_hora.desc()).limit(20).all()

@app.post("/setup-inicial")
def setup_inicial(db: Session = Depends(get_db)):
    # Crear Depto y Admin por defecto para poder probar
    if not db.query(DepartamentoDB).first():
        depto = DepartamentoDB(numero="101", torre="A")
        db.add(depto)
        db.commit()
        db.refresh(depto)
        
        admin = UsuarioDB(
            nombre="Administrador Torre A",
            email="admin@iot.com",
            password_hash="123456",
            rol="ADMINISTRADOR",
            id_departamento=depto.id_departamento
        )
        db.add(admin)
        db.commit()
        return {"mensaje": "Datos iniciales creados. ID Admin: 1"}
    return {"mensaje": "Datos ya existían"}