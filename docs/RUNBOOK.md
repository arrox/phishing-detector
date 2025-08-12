# 📖 Runbook Operacional - Phishing Detector

## 🎯 Información General

**Servicio:** Phishing Detector API  
**Propósito:** Detección automatizada de emails de phishing usando análisis heurístico + Gemini 2.5  
**Criticidad:** Alta - Servicio de seguridad crítico  
**SLO:** 99.5% disponibilidad, <2s latencia P95  

### Contactos de Emergencia

- **On-Call Primary:** @security-oncall (Slack)
- **On-Call Secondary:** @devops-oncall (Slack)  
- **Escalation:** @tech-lead, @security-manager
- **Email:** alerts-phishing-detector@company.com

---

## 🚨 Alertas y Respuestas

### CRITICAL: Service Down

**Alerta:** `PhishingDetectorDown`  
**Trigger:** Servicio no responde por >1 minuto  
**Impacto:** Usuario final no puede usar detección de phishing  

#### Respuesta Inmediata (0-5 min)

1. **Verificar estado del servicio**
   ```bash
   gcloud run services describe phishing-detector-prod \
     --region=us-central1 \
     --format="yaml(status.conditions)"
   ```

2. **Check health endpoints**
   ```bash
   SERVICE_URL=$(gcloud run services describe phishing-detector-prod \
     --region=us-central1 --format="value(status.url)")
   curl -f "$SERVICE_URL/health"
   ```

3. **Verificar logs inmediatos**
   ```bash
   gcloud logs read "resource.type=cloud_run_revision" \
     --limit=20 --format="table(timestamp,severity,textPayload)"
   ```

#### Investigación (5-15 min)

1. **Analizar causa raíz**
   - ❌ Deployment reciente fallido → Rollback inmediato
   - ❌ Problemas de recursos → Escalar o reiniciar
   - ❌ Problemas de dependencias → Verificar Gemini API, secrets
   - ❌ Problemas de red → Verificar VPC, firewall rules

2. **Rollback si es deployment reciente**
   ```bash
   # Ver revisiones recientes
   gcloud run revisions list --service=phishing-detector-prod \
     --region=us-central1 --limit=5
   
   # Rollback a versión anterior
   PREVIOUS_REVISION="phishing-detector-prod-00001-abc"
   gcloud run services update-traffic phishing-detector-prod \
     --to-revisions=$PREVIOUS_REVISION=100 --region=us-central1
   ```

3. **Reiniciar servicio si no es deployment**
   ```bash
   # Forzar nuevo deployment (mismo código)
   gcloud run deploy phishing-detector-prod \
     --image=gcr.io/PROJECT_ID/phishing-detector:latest \
     --region=us-central1
   ```

### CRITICAL: High Error Rate

**Alerta:** `PhishingDetectorCriticalErrorRate`  
**Trigger:** >15% errores 5xx por >1 minuto  
**Impacto:** Degradación severa del servicio  

#### Respuesta Inmediata (0-5 min)

1. **Identificar tipo de errores**
   ```bash
   gcloud logs read "resource.type=cloud_run_revision AND severity>=ERROR" \
     --limit=50 --format="table(timestamp,jsonPayload.error_type,textPayload)"
   ```

2. **Verificar dependencias críticas**
   ```bash
   # Test Gemini API directamente
   GEMINI_KEY=$(gcloud secrets versions access latest --secret="gemini-api-key")
   curl -H "Content-Type: application/json" \
        -d '{"contents":[{"parts":[{"text":"test"}]}]}' \
        "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key=$GEMINI_KEY"
   ```

3. **Verificar configuración de secrets**
   ```bash
   gcloud secrets versions list gemini-api-key --limit=3
   gcloud secrets versions list api-token-prod --limit=3
   ```

#### Acciones de Mitigación

- **Error rate 15-25%**: Monitoreo intensivo, preparar rollback
- **Error rate >25%**: Rollback inmediato
- **Error rate >50%**: Escalación a tech-lead + rollback inmediato

### WARNING: High Latency

**Alerta:** `PhishingDetectorHighLatency`  
**Trigger:** P95 >2 segundos por >5 minutos  
**Impacto:** Experiencia de usuario degradada  

#### Investigación

1. **Analizar bottlenecks**
   ```bash
   # Verificar métricas de CPU/memoria
   gcloud monitoring metrics list --filter="resource.type=cloud_run_revision"
   
   # Ver traces de latencia
   gcloud logging read "resource.type=cloud_run_revision" \
     --format="table(timestamp,jsonPayload.latency_ms)" \
     --filter="jsonPayload.latency_ms>2000"
   ```

2. **Verificar Gemini API latency**
   ```bash
   gcloud logs read "resource.type=cloud_run_revision" \
     --format="table(timestamp,jsonPayload.gemini_latency_ms)" \
     --filter="jsonPayload.gemini_latency_ms>5000"
   ```

3. **Escalar si es necesario**
   ```bash
   # Aumentar instancias mínimas temporalmente
   gcloud run services update phishing-detector-prod \
     --min-instances=5 --region=us-central1
   ```

### WARNING: Security Events

**Alerta:** `PhishingDetectorAuthFailures`  
**Trigger:** >1 fallo autenticación/segundo por >2 minutos  
**Impacto:** Posible ataque de seguridad  

#### Respuesta de Seguridad

1. **Analizar patrones de ataque**
   ```bash
   gcloud logs read "resource.type=cloud_run_revision" \
     --filter="jsonPayload.error_type=authentication_failed" \
     --format="table(timestamp,httpRequest.remoteIp,httpRequest.userAgent)" \
     --limit=100
   ```

2. **Identificar IPs maliciosas**
   ```bash
   gcloud logs read "resource.type=cloud_run_revision" \
     --filter="jsonPayload.error_type=authentication_failed" \
     --format="value(httpRequest.remoteIp)" | \
     sort | uniq -c | sort -nr | head -10
   ```

3. **Implementar mitigaciones**
   - Escalar a security-team inmediatamente
   - Considerar Cloud Armor WAF rules
   - Monitoreo intensivo por 24 horas

---

## 📊 Dashboards y Métricas

### Dashboards Principales

1. **[Cloud Run Overview](https://console.cloud.google.com/run/detail/us-central1/phishing-detector-prod/metrics)**
   - Request rate, latency, errors
   - CPU, memoria, instancias
   - Cold starts, timeout

2. **[Application Metrics](https://console.cloud.google.com/monitoring)**  
   - Clasificaciones por tipo
   - Gemini API performance
   - Authentication events

3. **[Security Dashboard](https://console.cloud.google.com/security)**
   - Failed authentications
   - Suspicious patterns
   - Rate limiting events

### Métricas Clave

```bash
# SLO Dashboard URLs
echo "Availability SLO: https://console.cloud.google.com/monitoring/slo"
echo "Latency SLO: https://console.cloud.google.com/monitoring/slo"
echo "Error Budget: https://console.cloud.google.com/monitoring/slo"
```

---

## 🔧 Comandos de Debugging

### Logs y Traces

```bash
# Logs en tiempo real
gcloud logs tail "resource.type=cloud_run_revision AND resource.labels.service_name=phishing-detector-prod"

# Errores recientes
gcloud logs read "resource.type=cloud_run_revision AND severity>=ERROR" \
  --limit=50 --format="table(timestamp,severity,jsonPayload.error,textPayload)"

# Performance traces
gcloud logging read "resource.type=cloud_run_revision" \
  --filter="jsonPayload.event='Classification completed'" \
  --format="table(timestamp,jsonPayload.latency_ms,jsonPayload.classification)"

# Security events
gcloud logs read "resource.type=cloud_run_revision" \
  --filter="jsonPayload.event='HTTP request processed' AND httpRequest.status>=400" \
  --format="table(timestamp,httpRequest.status,httpRequest.remoteIp,httpRequest.userAgent)"
```

### Performance Analysis

```bash
# Análisis de latencia
gcloud monitoring metrics list --filter="metric.type:run.googleapis.com/request_latencies"

# CPU/Memory trends
gcloud monitoring metrics list --filter="resource.type=cloud_run_revision" \
  | grep -E "(cpu|memory)"

# Scaling metrics
gcloud run services describe phishing-detector-prod \
  --region=us-central1 \
  --format="yaml(status.traffic,status.latestCreatedRevisionName)"
```

### Dependency Health

```bash
# Test Gemini API
test_gemini() {
  local key=$(gcloud secrets versions access latest --secret="gemini-api-key")
  curl -s -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -d '{"contents":[{"parts":[{"text":"test connection"}]}]}' \
    "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key=$key"
}

# Test service endpoints
test_endpoints() {
  local url=$(gcloud run services describe phishing-detector-prod \
    --region=us-central1 --format="value(status.url)")
  echo "Testing $url"
  curl -s -w "%{http_code}" "$url/health"
  curl -s -w "%{http_code}" "$url/ready"
  curl -s -w "%{http_code}" "$url/metrics"
}
```

---

## 🛠️ Procedimientos de Mantenimiento

### Deployment Rutinario

```bash
# Verificar estado pre-deployment
echo "=== Pre-deployment Checklist ==="
echo "✅ All alerts clear?"
echo "✅ No ongoing incidents?"
echo "✅ Performance within normal ranges?"
echo "✅ Tests passing?"

# Deployment con canary (automático en pipeline)
echo "Deployment will use canary strategy: 5% -> 25% -> 100%"

# Post-deployment verification
echo "=== Post-deployment Checklist ==="
echo "✅ Health checks pass?"
echo "✅ No new errors in logs?"
echo "✅ Latency within SLO?"
echo "✅ All metrics stable?"
```

### Rotación de Secretos

```bash
# Rotar Gemini API key (mensualmente)
rotate_gemini_key() {
  echo "1. Generate new key in Google AI Studio"
  echo "2. Update secret:"
  echo "   gcloud secrets versions add gemini-api-key --data-file=-"
  echo "3. Test service still works"
  echo "4. Document rotation in change log"
}

# Rotar API tokens (mensualmente)
rotate_api_token() {
  local new_token=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
  echo "New API token: $new_token"
  echo "gcloud secrets versions add api-token-prod --data-file=- <<< '$new_token'"
}
```

### Health Check Scheduling

```bash
# Health check completo (ejecutar semanalmente)
weekly_health_check() {
  echo "=== Weekly Health Check ==="
  
  # 1. Service health
  make health
  
  # 2. Performance review
  echo "Review performance dashboards"
  echo "Check SLO compliance"
  
  # 3. Security review
  echo "Review security logs"
  echo "Check authentication patterns"
  
  # 4. Cost review
  echo "Review Cloud billing"
  echo "Optimize resources if needed"
  
  # 5. Dependency health
  test_gemini
  test_endpoints
}
```

---

## 📈 Capacity Planning

### Scaling Triggers

```bash
# Auto-scaling configurado:
# - CPU > 70% por 2 minutos → Scale up
# - Requests/container > 60 por 1 minuto → Scale up
# - CPU < 30% por 10 minutos → Scale down

# Manual scaling para eventos
scale_for_high_traffic() {
  gcloud run services update phishing-detector-prod \
    --min-instances=10 \
    --max-instances=200 \
    --region=us-central1
}

# Restaurar scaling normal
restore_normal_scaling() {
  gcloud run services update phishing-detector-prod \
    --min-instances=2 \
    --max-instances=100 \
    --region=us-central1
}
```

### Performance Tuning

```bash
# CPU/Memory optimization
optimize_resources() {
  echo "Current config:"
  gcloud run services describe phishing-detector-prod \
    --region=us-central1 \
    --format="yaml(spec.template.spec.containers[0].resources)"
  
  echo "Recommended for high traffic:"
  echo "  cpu: 4"
  echo "  memory: 8Gi"
  echo "  concurrency: 80"
}
```

---

## 🔄 Disaster Recovery

### Backup y Recovery

```bash
# Backup crítico (configuración)
backup_configuration() {
  # Terraform state
  cd terraform && terraform state pull > backup-$(date +%Y%m%d).tfstate
  
  # Service configuration
  gcloud run services describe phishing-detector-prod \
    --region=us-central1 --format="export" > service-backup-$(date +%Y%m%d).yaml
  
  # Secrets list (no valores)
  gcloud secrets list --format="yaml" > secrets-list-$(date +%Y%m%d).yaml
}

# Recovery completo
disaster_recovery() {
  echo "=== DISASTER RECOVERY PROCEDURE ==="
  echo "1. Assess scope of disaster"
  echo "2. Activate incident response team"
  echo "3. Execute infrastructure recovery:"
  echo "   cd terraform && terraform apply"
  echo "4. Restore secrets from secure backup"
  echo "5. Deploy last known good version"
  echo "6. Verify service functionality"
  echo "7. Communicate to stakeholders"
}
```

### RTO/RPO Targets

- **RTO (Recovery Time Objective):** 15 minutos
- **RPO (Recovery Point Objective):** 5 minutos  
- **MTTR (Mean Time To Recovery):** 10 minutos
- **MTBF (Mean Time Between Failures):** 30 días

---

## 📞 Communication Templates

### Incident Communication

```markdown
# INCIDENT ALERT: Phishing Detector Service

**Status:** INVESTIGATING/IDENTIFIED/MONITORING/RESOLVED  
**Severity:** P0/P1/P2/P3  
**Started:** YYYY-MM-DD HH:MM UTC  
**Services Affected:** Phishing Detection API  

## Impact
- Users cannot detect phishing emails
- Gmail Add-on not functioning

## Current Status
[Brief description of current situation]

## Actions Taken
- [Action 1]
- [Action 2]

## Next Steps
- [Next action with ETA]

## Updates
Next update in 15 minutes or sooner if status changes.

---
Incident Commander: @oncall-engineer
```

### Post-Incident Report Template

```markdown
# Post-Incident Report: [Incident Title]

**Incident Date:** YYYY-MM-DD  
**Duration:** X hours Y minutes  
**Severity:** P1  

## Executive Summary
[Brief summary of what happened and impact]

## Timeline
- HH:MM - Issue first detected
- HH:MM - Investigation started  
- HH:MM - Root cause identified
- HH:MM - Fix applied
- HH:MM - Service restored

## Root Cause
[Detailed explanation of what caused the incident]

## Resolution
[How the issue was resolved]

## Action Items
- [ ] Action 1 - Owner - Due Date
- [ ] Action 2 - Owner - Due Date

## Lessons Learned
[What we learned and how to prevent this in the future]
```

---

## 📋 Checklists

### Pre-Deployment Checklist

- [ ] ✅ All tests passing in CI/CD
- [ ] ✅ Security scans clear  
- [ ] ✅ Performance tests passed
- [ ] ✅ Staging environment validated
- [ ] ✅ Rollback plan confirmed
- [ ] ✅ Monitoring alerts functional
- [ ] ✅ On-call engineer available
- [ ] ✅ Change window approved

### Post-Incident Checklist

- [ ] ✅ Service fully restored
- [ ] ✅ All alerts cleared
- [ ] ✅ Performance back to normal
- [ ] ✅ Stakeholders notified
- [ ] ✅ Post-mortem scheduled  
- [ ] ✅ Action items created
- [ ] ✅ Monitoring enhanced
- [ ] ✅ Documentation updated

### Monthly Review Checklist

- [ ] ✅ SLO compliance reviewed
- [ ] ✅ Cost optimization checked
- [ ] ✅ Security review completed
- [ ] ✅ Performance trends analyzed
- [ ] ✅ Capacity planning updated
- [ ] ✅ Secrets rotated
- [ ] ✅ Dependencies updated
- [ ] ✅ Documentation updated

---

**Mantenido por:** DevOps Team  
**Última actualización:** 2024-01-12  
**Próxima revisión:** 2024-04-12