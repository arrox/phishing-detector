# Detector de Phishing - Microservicio con Google Workspace Add-on

Sistema completo de detección de phishing que combina análisis heurístico con Gemini 2.5 para clasificar emails con alta precisión, priorizando la minimización de falsos negativos.

## 🏗️ Arquitectura

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Gmail Add-on   │────│  FastAPI        │────│  Gemini 2.5     │
│  (Apps Script)  │    │  Microservice   │    │  API            │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
        │ POST /classify        │ Pipeline <700ms       │ LLM <1200ms
        │ Bearer Auth           │ Headers + URLs + NLP  │ Final Analysis
        │                       │                       │
        │              ┌────────┴────────┐             │
        │              │                 │             │
        │         Análisis Paralelo  Redacción PII     │
        │         + Heurística       + Fallback        │
        │              │                 │             │
        │              └────────┬────────┘             │
        │                       │                      │
        └───────────────────────▼──────────────────────┘
                        Clasificación Final
                        phishing | sospechoso | seguro
```

## 🎯 Características Principales

- **Pipeline híbrido**: Análisis heurístico rápido + dictamen final con Gemini 2.5
- **SLO estricto**: p95 ≤ 2-3 segundos de latencia total
- **Privacidad**: Redacción automática de PII antes de logging/LLM
- **Fallback robusto**: Respuesta conservadora si Gemini falla
- **Add-on Gmail**: Interfaz visual con semáforo (🔴🟡🟢) y mensajes en español neutro
- **Seguridad**: Políticas de elevación para minimizar falsos negativos

## 🚀 Inicio Rápido

### 1. Configuración del Backend

```bash
# Clonar y configurar
git clone <repository>
cd phishing-detector

# Variables de entorno
cp .env.example .env
# Editar .env con tus credenciales

# Con Docker (recomendado)
docker-compose up -d

# O instalación local
pip install -e .
export GEMINI_API_KEY="your-key"
export API_TOKEN="your-secure-token"
python -m uvicorn src.app:app --reload
```

### 2. Verificar Funcionamiento

```bash
# Health check
curl http://localhost:8000/health

# Test de clasificación
curl -X POST http://localhost:8000/classify \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_headers": "From: test@example.com",
    "text_body": "Test email content",
    "raw_html": "<p>Test</p>",
    "attachments_meta": [],
    "account_context": {"user_locale": "es-ES"}
  }'
```

### 3. Configurar Add-on de Gmail

1. Ve a [Google Apps Script](https://script.google.com)
2. Crea nuevo proyecto
3. Copia el contenido de `gmail-addon/Code.gs`
4. Copia `gmail-addon/appsscript.json` como manifiesto
5. Configurar propiedades del script:
   ```javascript
   PropertiesService.getScriptProperties().setProperty('API_TOKEN', 'tu-token');
   ```
6. Desplegar como Add-on de Gmail

## 📊 Ejemplo de Uso

### Request de Clasificación

```json
{
  "raw_headers": "From: PayPal <noreply@payp4l-security.com>...",
  "raw_html": "<html><body>Urgent account verification...</body></html>",
  "text_body": "Your PayPal account requires immediate verification...",
  "attachments_meta": [],
  "account_context": {
    "user_locale": "es-ES",
    "trusted_senders": ["service@paypal.com"],
    "owned_domains": ["empresa.com"]
  }
}
```

### Response de Clasificación

```json
{
  "classification": "phishing",
  "risk_score": 87,
  "top_reasons": [
    "Dominio similar a marca conocida",
    "DMARC authentication failed", 
    "Solicitud urgente de credenciales"
  ],
  "non_technical_summary": "Este mensaje intenta robar tu información personal usando una dirección falsa de PayPal.",
  "recommended_actions": [
    "No hagas clic en ningún enlace",
    "Reporta este mensaje como spam"
  ],
  "evidence": {
    "header_findings": {
      "spf_dkim_dmarc": "fail",
      "reply_to_mismatch": true,
      "display_name_spoof": true
    },
    "url_findings": [
      {"url": "http://payp4l-security.com", "reason": "look-alike domain"}
    ],
    "nlp_signals": ["urgency", "credential_request"]
  },
  "latency_ms": 1847
}
```

### Interfaz del Add-on Gmail

```
┌─────────────────────────────────┐
│ 🔴 PELIGROSO                    │
│ Puntuación: 87/100              │
├─────────────────────────────────┤
│ Resumen:                        │
│ Este mensaje intenta robar tu   │
│ información usando una URL falsa│
│                                 │
│ Razones principales:            │
│ 1. Dominio similar a marca      │
│ 2. DMARC failed                 │
│ 3. Solicitud urgente            │
│                                 │
│ Acciones recomendadas:          │
│ • No hacer clic en enlaces      │
│ • Reportar como spam            │
├─────────────────────────────────┤
│ [Ver detalles técnicos]         │
└─────────────────────────────────┘
```

## ⚙️ Configuración

### Variables de Entorno

```bash
# API Keys (REQUERIDAS)
GEMINI_API_KEY=your-gemini-api-key
API_TOKEN=your-secure-api-token

# Configuración del servidor
HOST=0.0.0.0
PORT=8000
WORKERS=2
LOG_LEVEL=info

# Seguridad
ALLOWED_ORIGINS=https://*.googleapis.com,https://*.google.com
ALLOWED_HOSTS=*

# URLs permitidas para CORS (Gmail Add-on)
CORS_ORIGINS=https://script.google.com,https://script.googleusercontent.com
```

### Configuración del Add-on

En Google Apps Script, configurar estas propiedades:

```javascript
// Configuración obligatoria
PropertiesService.getScriptProperties().setProperties({
  'API_TOKEN': 'tu-token-de-api-seguro',
  'API_ENDPOINT': 'https://tu-microservicio.run.app/classify'
});
```

## 🧪 Tests

```bash
# Ejecutar todos los tests
pytest

# Con cobertura
pytest --cov=src --cov-report=html

# Tests específicos
pytest tests/test_service.py -v
pytest tests/test_api.py -v
pytest tests/test_header_analysis.py -v
```

### Golden Tests para Regresión

```bash
# Generar casos de prueba golden
python scripts/generate_golden_tests.py

# Ejecutar tests de regresión
pytest tests/test_golden_cases.py
```

## 🚀 Despliegue en Producción

### Google Cloud Run (Recomendado)

```bash
# 1. Build y push de imagen
docker build -t gcr.io/your-project/phishing-detector .
docker push gcr.io/your-project/phishing-detector

# 2. Deploy en Cloud Run
gcloud run deploy phishing-detector \
  --image gcr.io/your-project/phishing-detector \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars GEMINI_API_KEY=${GEMINI_API_KEY} \
  --set-env-vars API_TOKEN=${API_TOKEN} \
  --memory 2Gi \
  --cpu 2 \
  --concurrency 100 \
  --max-instances 10
```

### AWS Lambda + API Gateway

```bash
# Usando Serverless Framework
npm install -g serverless
serverless deploy --stage prod
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: phishing-detector
spec:
  replicas: 3
  selector:
    matchLabels:
      app: phishing-detector
  template:
    spec:
      containers:
      - name: phishing-detector
        image: your-registry/phishing-detector:latest
        ports:
        - containerPort: 8000
        env:
        - name: GEMINI_API_KEY
          valueFrom:
            secretKeyRef:
              name: phishing-secrets
              key: gemini-api-key
```

## 📈 Observabilidad

### Métricas Disponibles

- `phishing_requests_total`: Total de requests por endpoint/status
- `phishing_request_duration_seconds`: Latencia de requests
- `phishing_classifications_total`: Clasificaciones por tipo
- `phishing_errors_total`: Errores por tipo

### Logs Estructurados

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "message": "Email classification completed",
  "request_id": "req_123456",
  "classification": "phishing",
  "risk_score": 85,
  "latency_ms": 1847,
  "within_slo": true
}
```

### Dashboards

- **Grafana**: Dashboard para métricas de latencia y throughput
- **Prometheus**: Alertas por SLO y errores
- **Cloud Logging**: Análisis de logs estructurados

## 🔒 Seguridad

### Redacción de PII

- **Emails**: `user@domain.com` → `u***@domain.com`
- **Teléfonos**: `555-123-4567` → `555-***-4567`
- **Cuentas**: `1234567890` → `12****7890`
- **Tarjetas**: `4111 1111 1111 1111` → `4111 **** **** 1111`

### Políticas de Seguridad

1. **Elevación conservadora**: Ante señales críticas, elevar clasificación
2. **Timeouts estrictos**: Límites duros para evitar DoS
3. **Rate limiting**: Protección contra abuso
4. **Auth token**: Bearer token para API
5. **CORS**: Restricción a dominios Google Workspace

## 🔧 Troubleshooting

### Problemas Comunes

**Error: "Gemini API timeout"**
```bash
# Verificar conectividad
curl -H "Authorization: Bearer $GEMINI_API_KEY" \
  https://generativelanguage.googleapis.com/v1/models
```

**Error: "Service unavailable"**
```bash
# Verificar health checks
curl http://localhost:8000/health
curl http://localhost:8000/ready
```

**Add-on no aparece en Gmail**
```javascript
// Verificar scopes en appsscript.json
"oauthScopes": [
  "https://www.googleapis.com/auth/gmail.addons.current.message.readonly"
]
```

### Debugging

```bash
# Logs en tiempo real
docker logs -f phishing-detector

# Métricas
curl http://localhost:8000/metrics

# Test específico
pytest tests/test_service.py::TestPhishingDetectionService::test_classify_phishing_email -v -s
```

## 📚 Plan de Mejoras

### Próximas Versiones

1. **Calibración con dataset**: Entrenamiento con casos reales
2. **A/B testing**: Optimización de umbrales de riesgo  
3. **Caché inteligente**: Redis para WHOIS/DNS lookups
4. **Brand allowlist**: Base de datos de dominios legítimos
5. **ML pipeline**: Modelo personalizado para features heurísticas
6. **Análisis de imagen**: Detección de logos falsos en attachments

### Métricas de Éxito

- **Latencia p95**: ≤ 2.5s (target: 2s)
- **Falsos positivos**: ≤ 2%
- **Falsos negativos**: ≤ 0.5% (crítico)
- **Uptime**: ≥ 99.9%
- **Cobertura**: ≥ 95% de emails corporativos

## 🤝 Contribución

1. Fork del repository
2. Crear branch de feature: `git checkout -b feature/nueva-funcionalidad`
3. Commit de cambios: `git commit -am 'Add nueva funcionalidad'`
4. Push a branch: `git push origin feature/nueva-funcionalidad`
5. Crear Pull Request

## 📄 Licencia

MIT License - ver `LICENSE` para detalles.

## 📞 Soporte

- **Issues**: GitHub Issues
- **Email**: security@empresa.com
- **Docs**: [Documentación completa](https://docs.empresa.com/phishing-detector)