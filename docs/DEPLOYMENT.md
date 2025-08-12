# Guía de Despliegue - Detector de Phishing

Esta guía cubre el despliegue del microservicio en diferentes plataformas de nube.

## 📋 Pre-requisitos

1. **Clave de API de Gemini 2.5**
   - Obtener en [Google AI Studio](https://aistudio.google.com/app/apikey)
   - Verificar cuotas y límites

2. **Token de API seguro**
   ```bash
   # Generar token seguro
   openssl rand -base64 32
   ```

3. **Dominio para el servicio** (recomendado para producción)

## 🚀 Google Cloud Run (Recomendado)

### Configuración Inicial

```bash
# 1. Configurar gcloud
gcloud auth login
gcloud config set project your-project-id

# 2. Habilitar APIs necesarias
gcloud services enable run.googleapis.com
gcloud services enable cloudbuild.googleapis.com
```

### Despliegue Automatizado

```bash
# 1. Crear secretos
gcloud secrets create gemini-api-key --data-file=<(echo -n "$GEMINI_API_KEY")
gcloud secrets create api-token --data-file=<(echo -n "$API_TOKEN")

# 2. Build y deploy en un comando
gcloud run deploy phishing-detector \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars API_TOKEN="$API_TOKEN" \
  --set-secrets GEMINI_API_KEY=gemini-api-key:latest \
  --memory 2Gi \
  --cpu 2 \
  --concurrency 100 \
  --max-instances 10 \
  --min-instances 1 \
  --execution-environment gen2 \
  --service-account phishing-detector@your-project.iam.gserviceaccount.com
```

### Configuración Avanzada

```yaml
# cloudbuild.yaml
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/$PROJECT_ID/phishing-detector', '.']
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'gcr.io/$PROJECT_ID/phishing-detector']
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: gcloud
    args:
      - 'run'
      - 'deploy'
      - 'phishing-detector'
      - '--image'
      - 'gcr.io/$PROJECT_ID/phishing-detector'
      - '--region'
      - 'us-central1'
      - '--platform'
      - 'managed'
      - '--allow-unauthenticated'
```

## 🔧 AWS Lambda + API Gateway

### Usando Serverless Framework

```bash
# 1. Instalar Serverless
npm install -g serverless
npm install serverless-python-requirements

# 2. Configurar credenciales AWS
aws configure
```

```yaml
# serverless.yml
service: phishing-detector

provider:
  name: aws
  runtime: python3.11
  region: us-east-1
  timeout: 30
  memorySize: 3008
  environment:
    GEMINI_API_KEY: ${env:GEMINI_API_KEY}
    API_TOKEN: ${env:API_TOKEN}

functions:
  classify:
    handler: src.lambda_handler.handler
    events:
      - http:
          path: classify
          method: post
          cors: true
  health:
    handler: src.lambda_handler.health
    events:
      - http:
          path: health
          method: get

plugins:
  - serverless-python-requirements

custom:
  pythonRequirements:
    dockerizePip: true
    slim: true
```

```python
# src/lambda_handler.py
import json
from mangum import Mangum
from src.app import app

handler = Mangum(app, lifespan="off")

def health(event, context):
    return {
        'statusCode': 200,
        'body': json.dumps({'status': 'healthy'})
    }
```

### Despliegue

```bash
serverless deploy --stage production
```

## ☸️ Kubernetes

### Configuración Base

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: phishing-detector
```

```yaml
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: phishing-secrets
  namespace: phishing-detector
type: Opaque
data:
  gemini-api-key: <base64-encoded-key>
  api-token: <base64-encoded-token>
```

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: phishing-detector
  namespace: phishing-detector
spec:
  replicas: 3
  selector:
    matchLabels:
      app: phishing-detector
  template:
    metadata:
      labels:
        app: phishing-detector
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
        - name: API_TOKEN
          valueFrom:
            secretKeyRef:
              name: phishing-secrets
              key: api-token
        - name: WORKERS
          value: "1"
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi" 
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
```

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: phishing-detector-service
  namespace: phishing-detector
spec:
  selector:
    app: phishing-detector
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8000
  type: LoadBalancer
```

### Despliegue

```bash
kubectl apply -f k8s/
```

## 🌐 Azure Container Instances

```bash
# 1. Crear resource group
az group create --name phishing-detector-rg --location eastus

# 2. Deploy container
az container create \
  --resource-group phishing-detector-rg \
  --name phishing-detector \
  --image your-registry/phishing-detector:latest \
  --dns-name-label phishing-detector-unique \
  --ports 8000 \
  --environment-variables \
    'API_TOKEN'="$API_TOKEN" \
  --secure-environment-variables \
    'GEMINI_API_KEY'="$GEMINI_API_KEY" \
  --cpu 2 \
  --memory 4
```

## 🔍 Monitoreo Post-Despliegue

### Verificación Básica

```bash
# Health checks
curl https://your-service-url/health
curl https://your-service-url/ready

# Test de clasificación
curl -X POST https://your-service-url/classify \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @test-email.json
```

### Métricas

```bash
# Prometheus metrics
curl https://your-service-url/metrics

# Key metrics to monitor:
# - phishing_request_duration_seconds (latency)
# - phishing_requests_total (throughput)  
# - phishing_classifications_total (accuracy)
# - phishing_errors_total (reliability)
```

### Alertas Recomendadas

```yaml
# alerting.yml
groups:
- name: phishing-detector
  rules:
  - alert: HighLatency
    expr: histogram_quantile(0.95, phishing_request_duration_seconds) > 3
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High latency detected"
      
  - alert: HighErrorRate  
    expr: rate(phishing_errors_total[5m]) > 0.1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"
      
  - alert: ServiceDown
    expr: up{job="phishing-detector"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Service is down"
```

## 🔧 Configuración del Add-on Gmail

### 1. Crear Proyecto en Apps Script

1. Ve a [Google Apps Script](https://script.google.com)
2. Clic en "Nuevo proyecto"
3. Nombra el proyecto: "Detector de Phishing"

### 2. Configurar Código

```javascript
// En el editor de Apps Script
function onGmailMessageOpen(e) {
  // Pegar código de gmail-addon/Code.gs
}
```

### 3. Configurar Manifiesto

1. Clic en "Configuración del proyecto" (⚙️)
2. Marcar "Mostrar archivo de manifiesto appsscript.json"
3. Pegar contenido de `gmail-addon/appsscript.json`

### 4. Configurar Propiedades

```javascript
// En el editor, ir a Configuración > Propiedades del script
PropertiesService.getScriptProperties().setProperties({
  'API_TOKEN': 'tu-token-de-api',
  'API_ENDPOINT': 'https://tu-servicio.run.app/classify'
});
```

### 5. Publicar Add-on

1. Clic en "Deploy" > "Nueva implementación"
2. Seleccionar tipo: "Add-on de Gmail"
3. Descripción: "Detector de phishing para Gmail"
4. Clic en "Deploy"

### 6. Instalar en Gmail

1. Ir a Gmail
2. Configuración (⚙️) > Ver todos los configuraciones
3. Pestaña "Add-ons"
4. Buscar tu add-on y activarlo

## 📊 Configuración de Observabilidad

### Prometheus + Grafana

```yaml
# docker-compose.monitoring.yml
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
      
volumes:
  grafana_data:
```

### Dashboard de Grafana

Importar dashboard con ID: `12345` o crear manual con métricas:
- Request duration (p50, p95, p99)
- Request rate (qps)
- Classification distribution
- Error rate
- Uptime

## 🚨 Troubleshooting Común

### Error: "Service Unavailable"
```bash
# Verificar logs del container
docker logs phishing-detector
kubectl logs -l app=phishing-detector
```

### Error: "Gemini API timeout"
```bash
# Verificar conectividad desde el container
curl -H "Authorization: Bearer $GEMINI_API_KEY" \
  https://generativelanguage.googleapis.com/v1/models
```

### Error: Add-on no aparece
1. Verificar scopes en `appsscript.json`
2. Re-autorizar permisos
3. Verificar estado del deployment

## 🔐 Consideraciones de Seguridad

### Network Security
- Usar HTTPS siempre
- Configurar WAF si disponible
- Restringir IPs si es posible

### Secrets Management
- Nunca hardcodear API keys
- Usar servicios de secrets (Google Secret Manager, AWS Secrets Manager)
- Rotar tokens regularmente

### Monitoring
- Alertas por intentos de acceso no autorizado
- Logging de todos los requests de autenticación
- Monitoreo de patrones anómalos de uso