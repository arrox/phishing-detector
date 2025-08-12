#!/bin/bash

# ============================================================================
# SECRETS SETUP SCRIPT
# Script para configuración inicial de secretos en Google Secret Manager
# Debe ejecutarse una vez por ambiente después del despliegue de Terraform
# ============================================================================

set -euo pipefail

# ============================================================================
# CONFIGURACIÓN Y VALIDACIÓN
# ============================================================================

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función de logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Función de ayuda
show_help() {
    cat << EOF
📦 PHISHING DETECTOR - SECRETS SETUP

Configura secretos iniciales en Google Secret Manager para el servicio.

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -p, --project PROJECT_ID    ID del proyecto GCP (requerido)
    -e, --environment ENV       Ambiente (dev|staging|production)
    -g, --gemini-key KEY        Gemini API Key (requerido)
    -a, --api-token TOKEN       API Token personalizado (opcional)
    -r, --region REGION         Región GCP (default: us-central1)
    --update                    Actualizar secretos existentes
    --dry-run                   Mostrar comandos sin ejecutar
    -h, --help                  Mostrar esta ayuda

EXAMPLES:
    # Setup inicial para desarrollo
    $0 -p my-project-dev -e dev -g "your-gemini-api-key"
    
    # Setup para producción con token personalizado
    $0 -p my-project-prod -e production -g "gemini-key" -a "custom-api-token"
    
    # Dry run para ver qué se ejecutará
    $0 -p my-project -e staging -g "key" --dry-run

PREREQUISITES:
    - gcloud CLI instalado y autenticado
    - Permisos de Secret Manager Admin
    - APIs habilitadas: secretmanager.googleapis.com

EOF
}

# Valores por defecto
PROJECT_ID=""
ENVIRONMENT=""
GEMINI_API_KEY=""
API_TOKEN=""
REGION="us-central1"
UPDATE_MODE=false
DRY_RUN=false

# Parsear argumentos
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--project)
            PROJECT_ID="$2"
            shift 2
            ;;
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -g|--gemini-key)
            GEMINI_API_KEY="$2"
            shift 2
            ;;
        -a|--api-token)
            API_TOKEN="$2"
            shift 2
            ;;
        -r|--region)
            REGION="$2"
            shift 2
            ;;
        --update)
            UPDATE_MODE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_error "Opción desconocida: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validar argumentos requeridos
if [[ -z "$PROJECT_ID" ]]; then
    log_error "PROJECT_ID es requerido (-p|--project)"
    exit 1
fi

if [[ -z "$ENVIRONMENT" ]]; then
    log_error "ENVIRONMENT es requerido (-e|--environment)"
    exit 1
fi

if [[ -z "$GEMINI_API_KEY" ]]; then
    log_error "GEMINI_API_KEY es requerido (-g|--gemini-key)"
    exit 1
fi

# Validar environment
if [[ ! "$ENVIRONMENT" =~ ^(dev|staging|production)$ ]]; then
    log_error "ENVIRONMENT debe ser: dev, staging, o production"
    exit 1
fi

# Generar API token si no se proporcionó
if [[ -z "$API_TOKEN" ]]; then
    API_TOKEN=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    log_info "API Token generado automáticamente"
fi

# ============================================================================
# FUNCIONES HELPER
# ============================================================================

# Ejecutar comando con soporte para dry-run
execute_command() {
    local cmd="$1"
    local description="$2"
    
    log_info "$description"
    
    if [[ "$DRY_RUN" == true ]]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} $cmd"
    else
        eval "$cmd"
        if [[ $? -eq 0 ]]; then
            log_success "✅ $description completado"
        else
            log_error "❌ Error ejecutando: $description"
            return 1
        fi
    fi
}

# Verificar si un secreto existe
secret_exists() {
    local secret_name="$1"
    gcloud secrets describe "$secret_name" --project="$PROJECT_ID" >/dev/null 2>&1
}

# Crear o actualizar secreto
manage_secret() {
    local secret_name="$1"
    local secret_value="$2"
    local description="$3"
    
    if secret_exists "$secret_name"; then
        if [[ "$UPDATE_MODE" == true ]]; then
            execute_command \
                "echo '$secret_value' | gcloud secrets versions add '$secret_name' --project='$PROJECT_ID' --data-file=-" \
                "Actualizando secreto: $secret_name"
        else
            log_warning "Secreto $secret_name ya existe. Usa --update para actualizar."
        fi
    else
        # Crear secreto
        execute_command \
            "gcloud secrets create '$secret_name' --project='$PROJECT_ID' --replication-policy='automatic' --labels='service=phishing-detector,environment=$ENVIRONMENT'" \
            "Creando secreto: $secret_name"
        
        # Agregar versión inicial
        execute_command \
            "echo '$secret_value' | gcloud secrets versions add '$secret_name' --project='$PROJECT_ID' --data-file=-" \
            "Agregando valor inicial al secreto: $secret_name"
    fi
}

# ============================================================================
# VERIFICACIONES PREVIAS
# ============================================================================

log_info "🔧 Iniciando configuración de secretos para Phishing Detector"
log_info "Proyecto: $PROJECT_ID"
log_info "Ambiente: $ENVIRONMENT"
log_info "Región: $REGION"

if [[ "$DRY_RUN" == true ]]; then
    log_warning "MODO DRY-RUN: No se ejecutarán comandos reales"
fi

# Verificar autenticación gcloud
log_info "Verificando autenticación gcloud..."
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -1 >/dev/null; then
    log_error "No hay cuenta activa en gcloud. Ejecuta: gcloud auth login"
    exit 1
fi

ACTIVE_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -1)
log_success "Autenticado como: $ACTIVE_ACCOUNT"

# Verificar proyecto existe
log_info "Verificando proyecto GCP..."
if ! gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
    log_error "Proyecto '$PROJECT_ID' no existe o no tienes acceso"
    exit 1
fi

log_success "Proyecto verificado: $PROJECT_ID"

# Verificar APIs requeridas
log_info "Verificando APIs habilitadas..."
REQUIRED_APIS=(
    "secretmanager.googleapis.com"
    "cloudresourcemanager.googleapis.com"
)

for api in "${REQUIRED_APIS[@]}"; do
    if ! gcloud services list --enabled --project="$PROJECT_ID" --format="value(name)" | grep -q "$api"; then
        log_error "API requerida no habilitada: $api"
        log_info "Habilítala con: gcloud services enable $api --project=$PROJECT_ID"
        exit 1
    fi
done

log_success "APIs requeridas están habilitadas"

# Verificar permisos
log_info "Verificando permisos de Secret Manager..."
if ! gcloud secrets list --project="$PROJECT_ID" --limit=1 >/dev/null 2>&1; then
    log_error "No tienes permisos de Secret Manager. Roles requeridos:"
    log_error "- roles/secretmanager.admin"
    log_error "- roles/secretmanager.secretAccessor"
    exit 1
fi

log_success "Permisos verificados"

# ============================================================================
# CONFIGURACIÓN DE SECRETOS
# ============================================================================

log_info "🔐 Configurando secretos..."

# 1. Secreto principal: Gemini API Key
manage_secret \
    "gemini-api-key" \
    "$GEMINI_API_KEY" \
    "Gemini API Key para análisis de IA"

# 2. API Token para el ambiente específico
SECRET_NAME="api-token-${ENVIRONMENT}"
if [[ "$ENVIRONMENT" == "production" ]]; then
    SECRET_NAME="api-token-prod"
fi

manage_secret \
    "$SECRET_NAME" \
    "$API_TOKEN" \
    "API Token para autenticación Bearer ($ENVIRONMENT)"

# 3. Secretos opcionales por ambiente
case "$ENVIRONMENT" in
    "production")
        # Secretos adicionales para producción
        log_info "Configurando secretos adicionales para producción..."
        
        # Database URL (si se usa en el futuro)
        if [[ -n "${DATABASE_URL:-}" ]]; then
            manage_secret \
                "database-url-prod" \
                "$DATABASE_URL" \
                "Database URL para producción"
        fi
        
        # SSL Certificate (si se usa dominio personalizado)
        if [[ -n "${SSL_CERT:-}" ]]; then
            manage_secret \
                "ssl-certificate-prod" \
                "$SSL_CERT" \
                "Certificado SSL para dominio personalizado"
        fi
        ;;
        
    "staging")
        log_info "Secretos para staging configurados"
        ;;
        
    "dev")
        log_info "Secretos para desarrollo configurados"
        ;;
esac

# ============================================================================
# CONFIGURACIÓN DE PERMISOS IAM
# ============================================================================

log_info "🔑 Configurando permisos IAM..."

# Service Account para Cloud Run
SERVICE_ACCOUNT="phishing-detector-run-sa@${PROJECT_ID}.iam.gserviceaccount.com"

# Verificar si existe el Service Account
if gcloud iam service-accounts describe "$SERVICE_ACCOUNT" --project="$PROJECT_ID" >/dev/null 2>&1; then
    log_success "Service Account encontrado: $SERVICE_ACCOUNT"
    
    # Asignar permisos para acceder a secretos
    for secret_name in "gemini-api-key" "$SECRET_NAME"; do
        execute_command \
            "gcloud secrets add-iam-policy-binding '$secret_name' --project='$PROJECT_ID' --member='serviceAccount:$SERVICE_ACCOUNT' --role='roles/secretmanager.secretAccessor'" \
            "Asignando acceso al secreto: $secret_name"
    done
else
    log_warning "Service Account no encontrado: $SERVICE_ACCOUNT"
    log_warning "Asegúrate de ejecutar Terraform primero para crear la infraestructura"
fi

# ============================================================================
# TESTING DE SECRETOS
# ============================================================================

if [[ "$DRY_RUN" != true ]]; then
    log_info "🧪 Verificando secretos creados..."
    
    # Listar secretos creados
    log_info "Secretos en el proyecto:"
    gcloud secrets list --project="$PROJECT_ID" --filter="labels.service=phishing-detector" --format="table(name,createTime,labels.environment)"
    
    # Verificar acceso a secretos (sin mostrar valores)
    for secret_name in "gemini-api-key" "$SECRET_NAME"; do
        if secret_exists "$secret_name"; then
            SECRET_VERSION=$(gcloud secrets versions list "$secret_name" --project="$PROJECT_ID" --limit=1 --format="value(name)")
            log_success "✅ Secreto verificado: $secret_name (versión: $SECRET_VERSION)"
        else
            log_error "❌ Secreto no encontrado: $secret_name"
        fi
    done
fi

# ============================================================================
# RESUMEN Y SIGUIENTE PASOS
# ============================================================================

log_success "🎉 Configuración de secretos completada!"

cat << EOF

📋 RESUMEN:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Proyecto:           $PROJECT_ID
✅ Ambiente:           $ENVIRONMENT  
✅ Región:             $REGION
✅ Gemini API Key:     ████████████ (configurado)
✅ API Token:          ████████████ (configurado)

📦 SECRETOS CREADOS:
• gemini-api-key              → Para análisis de IA
• $SECRET_NAME    → Para autenticación API

🔐 PERMISOS IAM:
• Service Account configurado para acceder a secretos
• Políticas IAM aplicadas correctamente

📚 SIGUIENTES PASOS:
1. Ejecutar deployment con GitHub Actions o manualmente
2. Verificar que el servicio puede acceder a los secretos
3. Probar endpoints de la API
4. Configurar monitoring y alertas

⚠️  IMPORTANTE:
• Guarda el API Token generado en un lugar seguro
• No compartas los secretos en código fuente
• Rota los secretos regularmente en producción

🚀 COMANDO DE DEPLOYMENT:
gcloud run deploy phishing-detector-$ENVIRONMENT \\
  --image=gcr.io/$PROJECT_ID/phishing-detector:latest \\
  --region=$REGION \\
  --set-secrets="GEMINI_API_KEY=gemini-api-key:latest,API_TOKEN=$SECRET_NAME:latest"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF

if [[ "$ENVIRONMENT" == "production" ]]; then
    log_warning "🔒 RECORDATORIO DE PRODUCCIÓN:"
    log_warning "• Revisa las políticas de rotación de secretos"
    log_warning "• Configura alertas para acceso a secretos"
    log_warning "• Documenta el proceso de recuperación"
fi

log_info "Para más información: https://cloud.google.com/secret-manager/docs"