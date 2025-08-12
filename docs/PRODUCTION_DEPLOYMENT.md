# 🚀 Guía de Deployment a Producción - Phishing Detector

## 📋 Índice

1. [Preparativos y Prerequisitos](#-preparativos-y-prerequisitos)
2. [Configuración Inicial](#-configuración-inicial)
3. [Deployment Step by Step](#-deployment-step-by-step)
4. [Validación Post-Deployment](#-validación-post-deployment)
5. [Monitoring y Observabilidad](#-monitoring-y-observabilidad)
6. [Troubleshooting](#-troubleshooting)
7. [Rollback y Recovery](#-rollback-y-recovery)
8. [Mantenimiento](#-mantenimiento)

---

## 🎯 Preparativos y Prerequisitos

### Herramientas Requeridas

```bash
# Verificar herramientas instaladas
gcloud version    # Google Cloud SDK >= 400.0.0
terraform version # Terraform >= 1.5.0
docker version   # Docker >= 24.0.0
kubectl version  # kubectl >= 1.28.0
git --version    # Git >= 2.40.0
make --version   # GNU Make >= 4.3
```

### Permisos y Accesos Requeridos

- ✅ **Google Cloud Project Admin** o roles equivalentes:
  - `roles/owner` o combinación de:
  - `roles/compute.admin`
  - `roles/run.admin`
  - `roles/secretmanager.admin`
  - `roles/monitoring.admin`
  - `roles/logging.admin`

- ✅ **GitHub Repository Admin** para:
  - Configurar secrets del repositorio
  - Gestionar branch protection rules
  - Configurar GitHub Actions

- ✅ **Gemini API Access**:
  - API key válida de Google AI Studio
  - Billing account configurada

---

## ⚙️ Configuración Inicial

### 1. Configuración de Google Cloud

```bash
# Autenticar y configurar proyecto
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud config set compute/region us-central1

# Habilitar APIs requeridas
gcloud services enable \
  run.googleapis.com \
  compute.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  monitoring.googleapis.com \
  logging.googleapis.com \
  clouderrorreporting.googleapis.com \
  cloudtrace.googleapis.com \
  iam.googleapis.com

# Verificar billing está habilitado
gcloud billing projects list --filter="projectId:YOUR_PROJECT_ID"
```

### 2. Configuración de GitHub Secrets

Navega a tu repositorio GitHub → Settings → Secrets and variables → Actions y configura:

```bash
# Secrets requeridos
GCP_PROJECT_ID=your-gcp-project-id
GCP_WORKLOAD_IDENTITY_PROVIDER=projects/123456789/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider
GCP_SERVICE_ACCOUNT=github-actions-sa@your-project-id.iam.gserviceaccount.com
GEMINI_API_KEY=your-gemini-api-key-here

# Secrets opcionales
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
ALERT_EMAIL=alerts@your-company.com
```

### 3. Configuración del Repositorio

```bash
# Clonar y configurar repositorio
git clone https://github.com/your-org/phishing-detector.git
cd phishing-detector

# Configurar variables locales
cp .env.example .env
# Editar .env con valores reales

# Setup inicial
make setup
```

---

## 🚀 Deployment Step by Step

### Paso 1: Preparación de Infraestructura

```bash
# 1. Inicializar Terraform
cd terraform
terraform init

# 2. Crear terraform.tfvars
cat > terraform.tfvars << EOF
project_id = "your-gcp-project-id"
environment = "production"
region = "us-central1"
github_repository = "your-org/phishing-detector"
alert_email = "alerts@your-company.com"

# Configuración de producción
min_instances_override = 2
max_instances_override = 100
memory_override = "8Gi"
cpu_override = 4
enable_monitoring = true
enable_load_balancer = true
enable_waf = true
EOF

# 3. Planificar infraestructura
terraform plan

# 4. Aplicar infraestructura
terraform apply
```

### Paso 2: Configuración de Secretos

```bash
# Ejecutar script de configuración de secretos
chmod +x deployment/secrets-setup.sh
./deployment/secrets-setup.sh \
  --project your-gcp-project-id \
  --environment production \
  --gemini-key "your-gemini-api-key" \
  --alert-email "alerts@your-company.com"

# Verificar secretos creados
gcloud secrets list --project=your-gcp-project-id
```

### Paso 3: Primera Construcción Local

```bash
# Regresar al directorio raíz
cd ..

# Ejecutar tests completos
make test-all

# Construir y probar imagen Docker
make docker-build
make docker-run

# En otra terminal, probar endpoints
curl http://localhost:8000/health
curl http://localhost:8000/ready
```

### Paso 4: Deployment Automático via GitHub Actions

```bash
# Crear branch de release
git checkout -b release/v1.0.0

# Commit y push cambios
git add .
git commit -m "feat: initial production deployment

🚀 Production deployment ready with:
- Complete Terraform infrastructure
- Security scanning pipeline
- Monitoring and observability
- Multi-environment support
- Automated CI/CD"

git push origin release/v1.0.0

# Crear Pull Request a main
# El pipeline CI se ejecutará automáticamente
```

### Paso 5: Promoción a Producción

```bash
# Una vez que el PR es aprobado y merged a main:
# 1. El pipeline de release se ejecuta automáticamente
# 2. Se construye y pushea la imagen Docker
# 3. Se despliega a staging automáticamente
# 4. Para producción, se requiere aprobación manual

# Monitorear el deployment en GitHub Actions
# https://github.com/your-org/phishing-detector/actions
```

---

## ✅ Validación Post-Deployment

### 1. Health Checks Básicos

```bash
# Obtener URL del servicio
SERVICE_URL=$(gcloud run services describe phishing-detector-prod \
  --region=us-central1 \
  --format="value(status.url)")

echo "Service URL: $SERVICE_URL"

# Tests básicos
curl -f "$SERVICE_URL/health"
curl -f "$SERVICE_URL/ready"
curl -f "$SERVICE_URL/metrics"
```

### 2. Test de API Completo

```bash
# Test de autenticación
curl -X POST "$SERVICE_URL/classify" \
  -H "Authorization: Bearer invalid-token" \
  -H "Content-Type: application/json" \
  -d '{"raw_headers":"test"}' \
  # Debe retornar 401

# Test con token válido (obtener de Secret Manager)
API_TOKEN=$(gcloud secrets versions access latest --secret="api-token-prod")

curl -X POST "$SERVICE_URL/classify" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_headers": "From: test@example.com\nSubject: Test Email",
    "text_body": "This is a test email for validation",
    "account_context": {"user_locale": "es"}
  }'
```

### 3. Verificación de Monitoring

```bash
# Verificar dashboards disponibles
echo "Cloud Run Metrics: https://console.cloud.google.com/run/detail/us-central1/phishing-detector-prod/metrics"
echo "Logs: https://console.cloud.google.com/logs/query"
echo "Error Reporting: https://console.cloud.google.com/errors"
echo "Cloud Trace: https://console.cloud.google.com/traces"

# Verificar alertas configuradas
gcloud alpha monitoring policies list --format="table(displayName,enabled)"
```

---

## 📊 Monitoring y Observabilidad

### Dashboards Principales

1. **Cloud Run Metrics**
   - CPU, memoria, latencia, requests/s
   - Error rates y códigos de estado
   - Instancias activas y scaling

2. **Application Metrics**
   - Clasificaciones por tipo (safe, suspicious, phishing)
   - Latencia de Gemini API
   - Rate limiting y autenticación

3. **Security Metrics**
   - Intentos de acceso no autorizado
   - Errores de autenticación
   - Patrones de tráfico sospechoso

### Alertas Configuradas

```bash
# Ver alertas activas
gcloud alpha monitoring policies list \
  --filter="enabled:true" \
  --format="table(displayName,conditions[].displayName)"

# Alertas críticas configuradas:
# - Service Down (< 1 min downtime)
# - High Error Rate (> 5% errors)
# - High Latency (P95 > 2 seconds)
# - Security Events (authentication failures)
# - Resource Usage (CPU > 80%, Memory > 85%)
```

---

## 🚨 Troubleshooting

### Problemas Comunes

#### 1. Service No Responde

```bash
# Verificar estado del servicio
gcloud run services describe phishing-detector-prod \
  --region=us-central1 \
  --format="yaml(status)"

# Ver logs recientes
gcloud logs read "resource.type=cloud_run_revision" \
  --limit=50 \
  --format="table(timestamp,severity,textPayload)"

# Verificar configuración de secretos
gcloud secrets versions list gemini-api-key
gcloud secrets versions list api-token-prod
```

#### 2. Errores de Autenticación

```bash
# Verificar IAM del Service Account
gcloud projects get-iam-policy your-project-id \
  --flatten="bindings[].members" \
  --format="table(bindings.role)" \
  --filter="bindings.members:phishing-detector-run-sa@*"

# Verificar acceso a secretos
gcloud secrets get-iam-policy gemini-api-key
```

#### 3. Alta Latencia o Timeouts

```bash
# Verificar recursos del servicio
gcloud run services describe phishing-detector-prod \
  --region=us-central1 \
  --format="yaml(spec.template.spec.containers[0].resources)"

# Análisis de traces
gcloud logging read "resource.type=cloud_run_revision AND severity>=WARNING" \
  --limit=20
```

### Comandos de Diagnóstico

```bash
# Debug completo del servicio
make logs-tail  # En tiempo real
make monitor    # Abrir dashboards
make health     # Health check local

# Verificar configuración de red
gcloud run services get-iam-policy phishing-detector-prod \
  --region=us-central1

# Test de conectividad
curl -v "$SERVICE_URL/health" \
  -H "User-Agent: HealthCheck/1.0"
```

---

## 🔄 Rollback y Recovery

### Rollback Automático

El sistema incluye rollback automático en caso de:
- Health checks fallando por >5 minutos
- Error rate >15% por >2 minutos
- Latencia P95 >10 segundos por >10 minutos

### Rollback Manual

```bash
# 1. Identificar revisión anterior estable
gcloud run revisions list \
  --service=phishing-detector-prod \
  --region=us-central1 \
  --format="table(name,active,creationTimestamp)"

# 2. Rollback a revisión específica
PREVIOUS_REVISION="phishing-detector-prod-00001-abc"
gcloud run services update-traffic phishing-detector-prod \
  --to-revisions=$PREVIOUS_REVISION=100 \
  --region=us-central1

# 3. Verificar rollback
curl -f "$SERVICE_URL/health"

# 4. Rollback usando Makefile
make rollback ENVIRONMENT=production
```

### Recovery Completo

```bash
# En caso de disaster completo:

# 1. Recrear infraestructura
cd terraform
terraform destroy  # Solo si es necesario
terraform apply

# 2. Reconfigurar secretos
./deployment/secrets-setup.sh \
  --project your-gcp-project-id \
  --environment production \
  --gemini-key "$GEMINI_API_KEY" \
  --update

# 3. Redeploy desde imagen conocida
gcloud run deploy phishing-detector-prod \
  --image=gcr.io/your-project/phishing-detector:v1.0.0 \
  --region=us-central1
```

---

## 🔧 Mantenimiento

### Mantenimiento Rutinario

#### Semanal
- Revisar dashboards de performance
- Verificar alertas no críticas
- Actualizar dependencias de desarrollo

#### Mensual
- Rotar secretos de API
- Revisar costos y optimizar recursos
- Actualizar imagen base del contenedor
- Revisar y ajustar alertas

#### Trimestral
- Audit de seguridad completo
- Revisar políticas de retención de logs
- Actualizar documentación
- Disaster recovery testing

### Comandos de Mantenimiento

```bash
# Rotación de secretos
./deployment/secrets-setup.sh \
  --project your-gcp-project-id \
  --environment production \
  --gemini-key "new-gemini-api-key" \
  --update

# Limpieza de revisiones antiguas
gcloud run revisions list \
  --service=phishing-detector-prod \
  --region=us-central1 \
  --format="value(name)" \
  --filter="creationTimestamp<'-30d'" \
  | xargs -I {} gcloud run revisions delete {} --region=us-central1 --quiet

# Análisis de costos
gcloud billing budgets list
gcloud logging read "resource.type=cloud_run_revision" \
  --format="value(timestamp,resource.labels.service_name)" \
  --filter="timestamp>'-7d'" | wc -l
```

### Checklist de Health Check

- [ ] ✅ Todos los endpoints responden (health, ready, classify)
- [ ] ✅ Latencia P95 < 2 segundos
- [ ] ✅ Error rate < 1%
- [ ] ✅ No alertas críticas activas
- [ ] ✅ Recursos dentro de límites normales
- [ ] ✅ Logs no muestran errores recurrentes
- [ ] ✅ Backup de configuración actualizado
- [ ] ✅ Secretos no vencidos
- [ ] ✅ Métricas de negocio dentro de rangos esperados

---

## 📞 Contacto y Soporte

### Escalation Path

1. **On-Call Engineer** → Slack #alerts-phishing-detector
2. **DevOps Team** → devops@company.com
3. **Security Team** → security@company.com
4. **Tech Lead** → tech-lead@company.com

### Enlaces Útiles

- 📊 [Production Dashboard](https://console.cloud.google.com/run/detail/us-central1/phishing-detector-prod/metrics)
- 📋 [Logs](https://console.cloud.google.com/logs/query)
- 🚨 [Alerts](https://console.cloud.google.com/monitoring/alerting)
- 🔧 [GitHub Actions](https://github.com/your-org/phishing-detector/actions)
- 📚 [API Documentation](https://your-service-url.a.run.app/docs)

---

**¡Deployment exitoso! 🎉**

El servicio Phishing Detector está ahora corriendo en producción con todas las medidas de seguridad, monitoreo y observabilidad configuradas.