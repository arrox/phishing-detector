# 🚀 Deployment Guide - Phishing Detector

## 📋 Git Flow Strategy

Este proyecto usa **Git Flow moderno** con deployment automático:

### **Branches y Ambientes**

| Branch | Ambiente | Deployment | URL |
|--------|----------|------------|-----|
| `main` | **Producción** | ✅ Auto | `https://phishing-detector-[PROJECT_ID].a.run.app` |
| `develop` | **Staging** | ✅ Auto | `https://phishing-detector-staging-[PROJECT_ID].a.run.app` |
| `feature/*` | Ninguno | ❌ Solo CI | - |

## 🔄 Flujo de Trabajo

### **1. Desarrollo de Features**
```bash
# Crear feature branch desde develop
git checkout develop
git pull origin develop
git checkout -b feature/nueva-funcionalidad

# Desarrollo y commits
git add .
git commit -m "feat: nueva funcionalidad"
git push origin feature/nueva-funcionalidad

# Crear Pull Request hacia develop
gh pr create --base develop --title "Nueva funcionalidad"
```

### **2. Deployment a Staging**
```bash
# Merge PR a develop → deployment automático a staging
git checkout develop
git merge feature/nueva-funcionalidad
git push origin develop
# 🎯 Se ejecuta CI/CD → deploy a staging automáticamente
```

### **3. Deployment a Producción**
```bash
# Crear PR de develop a main
gh pr create --base main --head develop --title "Release v1.0.0"

# Una vez aprobado y merged → deployment automático a producción
git checkout main
git merge develop  
git push origin main
# 🚀 Se ejecuta deployment a producción automáticamente
```

## 🛡️ Branch Protection Rules

### **Configuración Requerida para `main`:**

1. **Ir a GitHub**: `Settings > Branches > Add rule`
2. **Branch name pattern**: `main`
3. **Configurar**:
   - ✅ Require pull request reviews before merging (1 review)
   - ✅ Require status checks to pass before merging
   - ✅ Require branches to be up to date before merging
   - ✅ Required status checks:
     - `Setup & Validation`
     - `Security Analysis`
     - `Tests & Quality (3.11)`
     - `Tests & Quality (3.12)`
     - `Build & Container Security`
   - ✅ Restrict pushes that create public merge commits
   - ❌ Allow force pushes
   - ❌ Allow deletions

## 🔐 Secrets Configuration

### **Secrets Requeridos en GitHub:**

| Secret | Ambiente | Descripción |
|--------|----------|-------------|
| `GCP_PROJECT_ID` | Todos | ID del proyecto GCP |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | Todos | Workload Identity Provider |
| `GCP_SERVICE_ACCOUNT` | Todos | Service Account para deployment |
| `GEMINI_API_KEY_PROD` | Producción | API Key de Gemini para producción |
| `API_TOKEN_PROD` | Producción | Token de API para producción |
| `GEMINI_API_KEY_STAGING` | Staging | API Key de Gemini para staging |
| `API_TOKEN_STAGING` | Staging | Token de API para staging |

### **Configurar Secrets:**
```bash
# Secrets de GCP (requeridos)
gh secret set GCP_PROJECT_ID --body "your-gcp-project-id"
gh secret set GCP_WORKLOAD_IDENTITY_PROVIDER --body "projects/123456789/locations/global/workloadIdentityPools/github/providers/github"
gh secret set GCP_SERVICE_ACCOUNT --body "github-actions@your-project.iam.gserviceaccount.com"

# Secrets de aplicación (producción)
gh secret set GEMINI_API_KEY_PROD --body "your-gemini-api-key"
gh secret set API_TOKEN_PROD --body "your-api-token"

# Secrets de aplicación (staging)
gh secret set GEMINI_API_KEY_STAGING --body "your-gemini-staging-key"
gh secret set API_TOKEN_STAGING --body "your-api-staging-token"
```

## 🏥 Health Checks

Ambos ambientes incluyen health checks automáticos:

### **Endpoints de Health:**
- `GET /health` - Estado básico del servicio
- `GET /ready` - Verificación completa de dependencias
- `GET /metrics` - Métricas de Prometheus

### **Verificación Manual:**
```bash
# Staging
curl https://phishing-detector-staging-[PROJECT_ID].a.run.app/health

# Producción  
curl https://phishing-detector-[PROJECT_ID].a.run.app/health
```

## 📊 Monitoring y Logs

### **Google Cloud Console:**
- **Logs**: `Cloud Logging > phishing-detector`
- **Métricas**: `Cloud Monitoring > Cloud Run`
- **Traces**: `Cloud Trace`

### **Comandos útiles:**
```bash
# Ver logs en tiempo real
gcloud logs tail "resource.type=cloud_run_revision AND resource.labels.service_name=phishing-detector"

# Métricas de la aplicación
curl https://your-service-url.app/metrics
```

## 🔄 Rollback

### **Rollback Automático:**
El sistema mantiene versiones anteriores disponibles en Cloud Run.

### **Rollback Manual:**
```bash
# Listar revisiones
gcloud run revisions list --service=phishing-detector --region=us-central1

# Hacer rollback a versión anterior
gcloud run services update-traffic phishing-detector \
  --to-revisions=phishing-detector-v20240818-abc123=100 \
  --region=us-central1
```

## 🚨 Troubleshooting

### **Deployment Falla:**
1. Verificar secrets configurados
2. Revisar logs de GitHub Actions
3. Verificar permisos de GCP Service Account
4. Confirmar configuración de Workload Identity

### **Health Checks Fallan:**
1. Verificar variables de entorno
2. Revisar logs de Cloud Run
3. Verificar conectividad a dependencias
4. Confirmar configuración de Gemini API

### **Comandos de Debug:**
```bash
# Estado del deployment
gh run list --limit 5

# Logs detallados del último run
gh run view --log

# Estado de Cloud Run
gcloud run services describe phishing-detector --region=us-central1
```

## 📈 Best Practices

1. **Siempre hacer PR**: Nunca push directo a `main` o `develop`
2. **CI debe pasar**: No mergear si CI está fallando
3. **Testing en staging**: Probar features en staging antes de producción
4. **Monitoring**: Revisar métricas después de deployments
5. **Rollback ready**: Tener plan de rollback si algo falla

---

**¿Necesitas ayuda?** Revisa los logs de GitHub Actions o contacta al equipo de DevOps.