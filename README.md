# TorrentGuard

TorrentGuard es una herramienta de seguridad para archivos torrent que utiliza la API de VirusTotal y análisis estático para detectar amenazas potenciales antes de la descarga.

## 🚀 Descarga Rápida (No Requiere Programación)

**¿No sabes programar? ¡No hay problema!**

Descarga el ejecutable listo para usar desde la sección [Releases](../../releases) de este repositorio:

1. **Descarga `TorrentGuard-v1.0.0.zip`** - Paquete completo que incluye:
   - `TorrentGuard.exe` - Ejecutable para Windows
   - `config.env` - Archivo de configuración (solo necesitas agregar tu API key)
   - Documentación básica de uso

2. **Configuración en 3 pasos:**
   - Extrae el ZIP en cualquier carpeta
   - Abre `config.env` con el Bloc de notas
   - Reemplaza `TU_API_KEY_AQUI` por tu API key gratuita de VirusTotal

3. **¡Listo para usar!**
   ```bash
   TorrentGuard.exe "ruta\al\archivo.torrent"
   ```
   o
   Agarrar el .torrent y soltar sobre el .exe
   
### 🔑 Obtener API Key de VirusTotal (Gratis)
1. Regístrate en [VirusTotal.com](https://www.virustotal.com/)
2. Ve a tu perfil → API Key
3. Copia la clave y pégala en el archivo `config.env`

---

## Características Principales

- 🔍 **Análisis profundo de archivos .torrent**
- 🛡️ **Integración con VirusTotal** para detección de malware
- 🌐 **Sistema avanzado de verificación de trackers:**
  - Evaluación individual de cada tracker
  - Puntuación de riesgo (0-100)
  - Identificación de protocolos inseguros
  - Detección de dominios sospechosos
- ⚠️ **Sistema inteligente de alertas y recomendaciones**
- 📊 **Reportes detallados de seguridad**
- 📄 **Actualización automática de base de datos de trackers**

## Fuentes de Datos de Trackers

TorrentGuard utiliza múltiples fuentes confiables para evaluar la seguridad de los trackers:

### Fuentes Principales
1. **Listas Blancas Verificadas**
   - [ngosang/trackerslist](https://github.com/ngosang/trackerslist): Lista curada y actualizada diariamente
   - [newTrackon](https://newtrackon.com/): Servicio de monitoreo de trackers públicos
   - Base de datos propia de trackers verificados de organizaciones confiables (Linux, Apache, Mozilla, etc.)

### Sistema de Evaluación de Riesgo
El análisis de trackers se basa en múltiples factores:
- Presencia en listas blancas verificadas
- Uso de protocolos seguros (HTTPS)
- Dominios y TLDs de riesgo conocido
- Tiempo de respuesta y disponibilidad
- Histórico de comportamiento malicioso

### Actualización de Datos
- Las listas de trackers se actualizan automáticamente cada 7 días
- Sistema de caché local para funcionamiento sin conexión
- Verificación en tiempo real de estados de trackers

---

## 🛠️ Instalación para Desarrolladores

### Requisitos Técnicos
- Python 3.13.2 o superior
- API Key de VirusTotal (gratuita)
- Conexión a Internet

### Instalación desde Código Fuente

1. **Clonar el Repositorio:**
```bash
git clone [url-del-repositorio]
cd PROYECTO-TORRENTGUARD
```

2. **Configurar Entorno Virtual:**
```bash
# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
# Windows:
.\venv\Scripts\activate
# Unix/MacOS:
source venv/bin/activate
```

3. **Instalar Dependencias:**
```bash
pip install -r requirements.txt
```

4. **Configurar API Key de VirusTotal:**
```bash
# Windows PowerShell:
$env:VIRUSTOTAL_API_KEY = "tu_api_key"
# Windows CMD:
set VIRUSTOTAL_API_KEY=tu_api_key
# Unix/MacOS:
export VIRUSTOTAL_API_KEY="tu_api_key"
```

### Uso del Programa

#### Modo Básico
```bash
python src/main.py "ruta/al/archivo.torrent"
```

#### Ejemplos
```bash
# Windows
python src/main.py "C:\Downloads\archivo.torrent"

# Unix/MacOS
python src/main.py "/home/usuario/downloads/archivo.torrent"
```

## 📈 Resultados del Análisis

El programa proporcionará un análisis detallado que incluye:

1. **Información del Archivo**
   - Nombre y tamaño del archivo torrent
   - Hash SHA-256 para verificación
   - Detalles del contenido y archivos incluidos

2. **Análisis de Trackers**
   - Verificación contra base de datos de trackers confiables
   - Identificación de trackers sospechosos
   - Evaluación de riesgo basada en la reputación

3. **Análisis de Seguridad**
   - Resultados de VirusTotal
   - Detección de archivos potencialmente peligrosos
   - Recomendaciones de seguridad

## 🔒 Análisis de Seguridad

El programa realiza las siguientes verificaciones:

1. **Análisis Estático:**
   - Verificación de extensiones peligrosas
   - Análisis de estructura del torrent
   - Verificación de metadatos

2. **Análisis VirusTotal:**
   - Escaneo con múltiples antivirus
   - Verificación de reputación
   - Historial de detecciones

3. **Análisis de Trackers:**
   - Verificación de trackers conocidos
   - Detección de trackers maliciosos
   - Evaluación de riesgo de red

## 📊 Niveles de Riesgo

- ✅ **BAJO:** No se detectaron amenazas
- ⚠️ **MEDIO:** Elementos que requieren atención
- ❌ **ALTO:** Amenazas detectadas, no recomendado

## ⚠️ Limitaciones

- Solo analiza archivos .torrent, no el contenido descargado
- Requiere conexión a Internet para VirusTotal
- Límites de API en la versión gratuita de VirusTotal

## 🤝 Contribuir y Reportar Issues

### ¿Encontraste un problema o quieres ayudar?
- **Beta Testing:** El proyecto necesita más pruebas con diferentes archivos torrent
- **Issues:** Reporta problemas en la sección Issues de GitHub
- **Sugerencias:** Ideas para nuevas características son bienvenidas

### Para reportar problemas:
1. Abre un issue en GitHub
2. Incluye el mensaje de error completo
3. Adjunta detalles del sistema operativo
4. Si es posible, comparte el archivo .torrent (sin contenido malicioso)

## 📁 Estructura del Proyecto

```
PROYECTO TORRENTGUARD/
├── src/
│   ├── main.py                 # Punto de entrada
│   └── torrentguard/
│       ├── analyzer.py         # Análisis de torrents
│       ├── security.py         # Verificaciones de seguridad
│       ├── tracker.py          # Análisis de trackers
│       └── virustotal.py       # Integración VirusTotal
├── tests/                      # Pruebas unitarias
└── requirements.txt           # Dependencias
```

## 🧪 Desarrollo y Contribución

### Configuración del Entorno de Desarrollo
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Para herramientas de desarrollo
```

### Ejecutar Tests
```bash
pytest
```

### Estilo de Código
- Seguimos PEP 8
- Usamos type hints
- Docstrings en formato Google
- Black para formateo de código

## 📜 Licencia

Este proyecto está bajo la licencia MIT. Ver archivo `LICENSE` para más detalles.

---

## 🌟 Estado del Proyecto

**Versión Actual:** v1.0.0 (Beta)  
**Estado:** En pruebas - Buscando feedback de la comunidad

¡Tu feedback es valioso! Prueba la herramienta y comparte tu experiencia.
