from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.config import settings
from app.database import create_db_and_tables
from app.domain.device.controller import router as device_router
from app.shared.middleware.cryptography import (
    DecryptionMiddleware,
    EncryptionMiddleware,
)

# Importar todos los modelos para que SQLModel pueda crear las tablas
from app.domain.personal_data.model import DatosPersonalesNoCriticos, DatosSensibles
from app.domain.admin.model import Administrador
from app.domain.manager.model import Gerente, GerenteServicio
from app.domain.user.model import Usuario
from app.domain.services.model import Servicio
from app.domain.applications.model import Aplicacion, AplicacionServicio
from app.domain.device.model import Device, DeviceService
from app.domain.roles.model import Rol, PermisoRol, UsuarioRol
from app.domain.tickets.model import TicketStatus, TicketServicio, TicketEcosistema


@asynccontextmanager
async def lifespan(_: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    debug=settings.DEBUG,
    lifespan=lifespan,
)

app.add_middleware(DecryptionMiddleware)  # Comentar si se estan en desarrollo
app.add_middleware(EncryptionMiddleware)  # Comentar si se estan en desarrollo

app.include_router(device_router, prefix="/api/v1")
