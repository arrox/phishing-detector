#!/bin/bash

# Script para configurar el proyecto GCP para el deployment
set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Configurando proyecto GCP para Phishing Detector${NC}"

# Verificar si gcloud está instalado
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}❌ gcloud CLI no está instalado. Instálalo desde: https://cloud.google.com/sdk/docs/install${NC}"
    exit 1
fi

# Solicitar información del proyecto
read -p "Ingresa tu PROJECT_ID de GCP: " PROJECT_ID
read -p "Ingresa la región (default: us-central1): " REGION
REGION=${REGION:-us-central1}

echo -e "${BLUE}📋 Configurando proyecto: ${PROJECT_ID} en región: ${REGION}${NC}"

# Configurar proyecto actual
echo -e "${YELLOW}⚙️ Configurando proyecto...${NC}"
gcloud config set project $PROJECT_ID

# Habilitar APIs necesarias
echo -e "${YELLOW}🔌 Habilitando APIs necesarias...${NC}"
gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    secretmanager.googleapis.com \
    monitoring.googleapis.com \
    logging.googleapis.com \
    cloudresourcemanager.googleapis.com \
    iam.googleapis.com \
    iamcredentials.googleapis.com \
    storage.googleapis.com

# Crear Artifact Registry para containers
echo -e "${YELLOW}📦 Configurando Artifact Registry...${NC}"
gcloud artifacts repositories create phishing-detector \
    --repository-format=docker \
    --location=$REGION \
    --description="Container registry for phishing detector service" || echo "Repository might already exist"

# Configurar Workload Identity Pool para GitHub Actions
echo -e "${YELLOW}🔐 Configurando Workload Identity Federation...${NC}"

# Crear workload identity pool
gcloud iam workload-identity-pools create github-actions \
    --location="global" \
    --description="GitHub Actions pool" || echo "Pool might already exist"

# Crear provider
gcloud iam workload-identity-pools providers create-oidc github-provider \
    --location="global" \
    --workload-identity-pool="github-actions" \
    --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.actor=assertion.actor" \
    --issuer-uri="https://token.actions.githubusercontent.com" || echo "Provider might already exist"

# Crear service account para GitHub Actions
echo -e "${YELLOW}👤 Creando service account...${NC}"
gcloud iam service-accounts create github-actions-sa \
    --description="Service account for GitHub Actions" \
    --display-name="GitHub Actions SA" || echo "Service account might already exist"

# Asignar roles necesarios al service account
echo -e "${YELLOW}🔑 Asignando permisos...${NC}"
SERVICE_ACCOUNT_EMAIL="github-actions-sa@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/run.admin"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/cloudbuild.builds.builder"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/artifactregistry.writer"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/secretmanager.admin"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/monitoring.metricWriter"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/logging.logWriter"

# Configurar binding para GitHub repo (necesario cambiar por tu repo)
echo -e "${YELLOW}📝 Nota: Debes configurar el binding para tu repositorio GitHub${NC}"
echo -e "Ejecuta este comando con tu repositorio:"
echo -e "${BLUE}gcloud iam service-accounts add-iam-policy-binding ${SERVICE_ACCOUNT_EMAIL} \\"
echo -e "    --role=\"roles/iam.workloadIdentityUser\" \\"
echo -e "    --member=\"principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-actions/attribute.repository/TU_GITHUB_USER/phishing-detector\"${NC}"

# Obtener project number
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format="value(projectNumber)")

# Crear archivo de configuración para Terraform
echo -e "${YELLOW}📄 Creando configuración para Terraform...${NC}"
cat > terraform/terraform.tfvars << EOF
# Configuración generada automáticamente
project_id      = "$PROJECT_ID"
project_number  = "$PROJECT_NUMBER"
region          = "$REGION"
environment     = "production"

# Service accounts
github_sa_email = "$SERVICE_ACCOUNT_EMAIL"

# Workload Identity
workload_identity_pool = "projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github-actions"
workload_identity_provider = "projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github-actions/providers/github-provider"
EOF

echo -e "${GREEN}✅ Configuración de GCP completada!${NC}"
echo -e "${BLUE}📝 Información importante guardada en terraform/terraform.tfvars${NC}"
echo
echo -e "${YELLOW}🔄 Próximos pasos:${NC}"
echo -e "1. Configura los secrets en GitHub (ver salida anterior)"
echo -e "2. Ejecuta: cd terraform && terraform init && terraform apply"
echo -e "3. Configura los secretos de la aplicación"
echo -e "4. Haz push a GitHub para activar CI/CD"
echo
echo -e "${GREEN}🎉 ¡Listo para deployment!${NC}"