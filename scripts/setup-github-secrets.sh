#!/bin/bash

# Script para configurar secretos de GitHub Actions
set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔐 Configurando secretos para GitHub Actions${NC}"

# Verificar si gh CLI está instalado
if ! command -v gh &> /dev/null; then
    echo -e "${YELLOW}⚠️ GitHub CLI no está instalado. Instálalo desde: https://cli.github.com${NC}"
    echo -e "${BLUE}📝 Configurarás los secretos manualmente en GitHub${NC}"
    MANUAL_SETUP=true
else
    MANUAL_SETUP=false
    # Verificar autenticación
    if ! gh auth status &> /dev/null; then
        echo -e "${YELLOW}🔑 Autenticando con GitHub...${NC}"
        gh auth login
    fi
fi

# Leer configuración de terraform.tfvars
if [[ -f "terraform/terraform.tfvars" ]]; then
    source <(grep -v '^#' terraform/terraform.tfvars | sed 's/ *= */=/g')
    echo -e "${GREEN}✅ Configuración leída de terraform.tfvars${NC}"
else
    echo -e "${RED}❌ No se encuentra terraform/terraform.tfvars. Ejecuta primero gcp-setup.sh${NC}"
    exit 1
fi

# Solicitar información adicional
echo -e "${BLUE}📋 Información adicional necesaria:${NC}"
read -p "Ingresa tu GEMINI_API_KEY: " GEMINI_API_KEY
read -p "Ingresa un API_TOKEN seguro para tu aplicación (o genera uno): " API_TOKEN

if [[ -z "$API_TOKEN" ]]; then
    echo -e "${YELLOW}🔑 Generando API_TOKEN aleatorio...${NC}"
    API_TOKEN=$(openssl rand -base64 32)
    echo -e "${GREEN}Token generado: ${API_TOKEN}${NC}"
fi

# Secretos a configurar
declare -A SECRETS=(
    ["GCP_PROJECT_ID"]="$project_id"
    ["GCP_PROJECT_NUMBER"]="$project_number"  
    ["GCP_REGION"]="$region"
    ["GCP_SERVICE_ACCOUNT"]="$github_sa_email"
    ["GCP_WORKLOAD_IDENTITY_PROVIDER"]="$workload_identity_provider"
    ["GEMINI_API_KEY"]="$GEMINI_API_KEY"
    ["API_TOKEN"]="$API_TOKEN"
)

if [[ "$MANUAL_SETUP" == "false" ]]; then
    echo -e "${YELLOW}⚙️ Configurando secretos automáticamente...${NC}"
    
    for secret_name in "${!SECRETS[@]}"; do
        secret_value="${SECRETS[$secret_name]}"
        echo -e "Setting ${secret_name}..."
        echo "$secret_value" | gh secret set "$secret_name"
    done
    
    echo -e "${GREEN}✅ Secretos configurados en GitHub Actions!${NC}"
else
    echo -e "${YELLOW}📝 Configuración manual requerida${NC}"
    echo -e "${BLUE}Ve a tu repositorio GitHub → Settings → Secrets and variables → Actions${NC}"
    echo -e "Configura estos secretos:"
    echo
    
    for secret_name in "${!SECRETS[@]}"; do
        secret_value="${SECRETS[$secret_name]}"
        echo -e "${YELLOW}${secret_name}${NC}: ${secret_value}"
    done
fi

# Guardar información para referencias futuras
cat > .env.production << EOF
# Configuración de producción - NO COMMITEAR
GCP_PROJECT_ID=$project_id
GCP_PROJECT_NUMBER=$project_number
GCP_REGION=$region
GCP_SERVICE_ACCOUNT=$github_sa_email
GCP_WORKLOAD_IDENTITY_PROVIDER=$workload_identity_provider
GEMINI_API_KEY=$GEMINI_API_KEY
API_TOKEN=$API_TOKEN

# URLs de servicios
PHISHING_API_ENDPOINT=https://phishing-detector-\${GCP_PROJECT_ID}.a.run.app
EOF

echo -e "${GREEN}✅ Configuración guardada en .env.production${NC}"
echo -e "${RED}⚠️ NO COMMITS el archivo .env.production${NC}"
echo
echo -e "${BLUE}🔄 Próximo paso: Ejecutar terraform apply${NC}"