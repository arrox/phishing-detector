#!/bin/bash

# Script de deployment completo para producción
set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

echo -e "${PURPLE}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              🛡️ PHISHING DETECTOR DEPLOYMENT             ║"
echo "║                 Production Setup Script                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Funciones de utilidad
log_step() {
    echo -e "${BLUE}📋 STEP: $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️ $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Verificar pre-requisitos
check_prerequisites() {
    log_step "Verificando pre-requisitos"
    
    local missing_tools=()
    
    if ! command -v gcloud &> /dev/null; then
        missing_tools+=("gcloud CLI")
    fi
    
    if ! command -v terraform &> /dev/null; then
        missing_tools+=("terraform")
    fi
    
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Faltan herramientas: ${missing_tools[*]}"
        echo "Instala las herramientas faltantes e intenta de nuevo."
        exit 1
    fi
    
    log_success "Todos los pre-requisitos están instalados"
}

# Configurar proyecto GCP
setup_gcp() {
    log_step "Configurando proyecto GCP"
    
    if [[ ! -f "terraform/terraform.tfvars" ]]; then
        log_warning "No se encontró configuración GCP. Ejecutando setup..."
        ./scripts/gcp-setup.sh
    else
        log_success "Configuración GCP encontrada"
    fi
}

# Configurar secretos GitHub
setup_github_secrets() {
    log_step "Configurando secretos de GitHub"
    
    if [[ ! -f ".env.production" ]]; then
        log_warning "No se encontró configuración de secretos. Ejecutando setup..."
        ./scripts/setup-github-secrets.sh
    else
        log_success "Secretos ya configurados"
    fi
}

# Desplegar infraestructura
deploy_infrastructure() {
    log_step "Desplegando infraestructura con Terraform"
    
    cd terraform
    
    # Initialize Terraform
    echo -e "${YELLOW}🔄 Inicializando Terraform...${NC}"
    terraform init -upgrade
    
    # Plan
    echo -e "${YELLOW}📋 Creando plan de ejecución...${NC}"
    terraform plan -out=tfplan
    
    # Apply with confirmation
    echo -e "${YELLOW}🚀 Aplicando cambios...${NC}"
    echo -e "${BLUE}¿Deseas continuar con el deployment? (yes/no): ${NC}"
    read -r confirm
    
    if [[ $confirm == "yes" || $confirm == "y" ]]; then
        terraform apply tfplan
        log_success "Infraestructura desplegada exitosamente"
    else
        log_warning "Deployment cancelado por el usuario"
        exit 1
    fi
    
    cd ..
}

# Configurar secretos en GCP
setup_application_secrets() {
    log_step "Configurando secretos de la aplicación en GCP"
    
    source .env.production
    
    # Crear secretos en Secret Manager
    echo -e "${YELLOW}🔐 Configurando secretos en Secret Manager...${NC}"
    
    # GEMINI_API_KEY
    echo "$GEMINI_API_KEY" | gcloud secrets create gemini-api-key \
        --data-file=- \
        --project=$GCP_PROJECT_ID || echo "Secret might already exist"
    
    # API_TOKEN
    echo "$API_TOKEN" | gcloud secrets create api-token \
        --data-file=- \
        --project=$GCP_PROJECT_ID || echo "Secret might already exist"
    
    log_success "Secretos configurados en GCP Secret Manager"
}

# Build y deploy de la aplicación
deploy_application() {
    log_step "Building y desplegando aplicación"
    
    source .env.production
    
    # Build con Cloud Build
    echo -e "${YELLOW}🔨 Building container image...${NC}"
    gcloud builds submit \
        --tag="${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/phishing-detector/phishing-detector:latest" \
        --project=$GCP_PROJECT_ID \
        .
    
    # Deploy a Cloud Run
    echo -e "${YELLOW}🚀 Desplegando a Cloud Run...${NC}"
    gcloud run deploy phishing-detector \
        --image="${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/phishing-detector/phishing-detector:latest" \
        --platform=managed \
        --region=$GCP_REGION \
        --allow-unauthenticated \
        --port=8000 \
        --memory=2Gi \
        --cpu=2 \
        --concurrency=100 \
        --max-instances=10 \
        --min-instances=1 \
        --set-secrets=GEMINI_API_KEY=gemini-api-key:latest,API_TOKEN=api-token:latest \
        --set-env-vars=LOG_LEVEL=info,WORKERS=1 \
        --project=$GCP_PROJECT_ID
    
    # Obtener URL del servicio
    SERVICE_URL=$(gcloud run services describe phishing-detector \
        --platform=managed \
        --region=$GCP_REGION \
        --project=$GCP_PROJECT_ID \
        --format="value(status.url)")
    
    echo -e "${GREEN}🌐 Servicio desplegado en: $SERVICE_URL${NC}"
    
    # Actualizar .env.production con la URL real
    sed -i.bak "s|PHISHING_API_ENDPOINT=.*|PHISHING_API_ENDPOINT=$SERVICE_URL|" .env.production
}

# Verificar deployment
verify_deployment() {
    log_step "Verificando deployment"
    
    source .env.production
    
    # Health check
    echo -e "${YELLOW}🏥 Verificando health check...${NC}"
    if curl -f "$SERVICE_URL/health" > /dev/null 2>&1; then
        log_success "Health check OK"
    else
        log_error "Health check failed"
        return 1
    fi
    
    # Ready check
    echo -e "${YELLOW}⚡ Verificando readiness...${NC}"
    if curl -f "$SERVICE_URL/ready" > /dev/null 2>&1; then
        log_success "Service ready"
    else
        log_error "Service not ready"
        return 1
    fi
    
    # Test API
    echo -e "${YELLOW}🧪 Probando API...${NC}"
    response=$(curl -s -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "raw_headers": "From: test@example.com",
            "text_body": "Test message",
            "raw_html": "<p>Test</p>",
            "attachments_meta": [],
            "account_context": {"user_locale": "es-ES"}
        }' \
        "$SERVICE_URL/classify")
    
    if echo "$response" | grep -q "classification"; then
        log_success "API test passed"
        echo -e "${BLUE}Respuesta: $(echo $response | jq -r .classification)${NC}"
    else
        log_error "API test failed"
        echo "Response: $response"
        return 1
    fi
}

# Setup monitoring
setup_monitoring() {
    log_step "Configurando monitoring"
    
    source .env.production
    
    # El monitoring ya está configurado en Terraform
    # Solo verificamos que esté funcionando
    
    echo -e "${YELLOW}📊 Verificando métricas...${NC}"
    sleep 10  # Dar tiempo para que aparezcan métricas
    
    # Verificar que las métricas estén llegando
    gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=phishing-detector" \
        --limit=5 \
        --project=$GCP_PROJECT_ID \
        --format="value(timestamp,textPayload)" || log_warning "No logs found yet"
    
    log_success "Monitoring configurado"
}

# Función principal
main() {
    echo -e "${BLUE}🚀 Iniciando deployment completo...${NC}"
    echo
    
    check_prerequisites
    echo
    
    setup_gcp
    echo
    
    setup_github_secrets
    echo
    
    deploy_infrastructure
    echo
    
    setup_application_secrets
    echo
    
    deploy_application
    echo
    
    verify_deployment
    echo
    
    setup_monitoring
    echo
    
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                🎉 DEPLOYMENT COMPLETADO                  ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    source .env.production
    echo -e "${GREEN}✅ Servicio desplegado en: $SERVICE_URL${NC}"
    echo -e "${BLUE}📊 Monitoring: https://console.cloud.google.com/run/detail/${GCP_REGION}/phishing-detector/metrics?project=${GCP_PROJECT_ID}${NC}"
    echo -e "${PURPLE}🏁 ¡Tu sistema de detección de phishing está listo!${NC}"
    echo
    echo -e "${YELLOW}🔄 Próximos pasos:${NC}"
    echo -e "1. Configurar el Gmail Add-on con la URL: $SERVICE_URL"
    echo -e "2. Revisar dashboards de monitoring"
    echo -e "3. Configurar alertas adicionales si es necesario"
    echo -e "4. Hacer push a GitHub para activar CI/CD automatizado"
}

# Manejo de errores
trap 'echo -e "${RED}❌ Error durante el deployment. Revisa los logs.${NC}"; exit 1' ERR

# Ejecutar función principal
main "$@"