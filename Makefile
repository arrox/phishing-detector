# Makefile para el sistema de detección de phishing
.PHONY: help setup deploy test clean monitoring

# Variables
PROJECT_DIR := $(shell pwd)
SCRIPTS_DIR := $(PROJECT_DIR)/scripts

# Colores para output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Mostrar ayuda
	@echo -e "$(BLUE)🛡️ PHISHING DETECTOR - DEPLOYMENT AUTOMATION$(NC)"
	@echo
	@echo -e "$(YELLOW)Comandos disponibles:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo
	@echo -e "$(BLUE)Orden recomendado para deployment inicial:$(NC)"
	@echo -e "  1. make setup-gcp"
	@echo -e "  2. make setup-secrets"
	@echo -e "  3. make deploy-all"
	@echo -e "  4. make setup-addon"
	@echo -e "  5. make test-production"

setup-gcp: ## Configurar proyecto GCP y APIs
	@echo -e "$(BLUE)🚀 Configurando proyecto GCP...$(NC)"
	@$(SCRIPTS_DIR)/gcp-setup.sh

setup-secrets: ## Configurar secretos de GitHub
	@echo -e "$(BLUE)🔐 Configurando secretos de GitHub...$(NC)"
	@$(SCRIPTS_DIR)/setup-github-secrets.sh

deploy-infrastructure: ## Desplegar solo infraestructura con Terraform
	@echo -e "$(BLUE)🏗️ Desplegando infraestructura...$(NC)"
	cd terraform && terraform init -upgrade && terraform plan -out=tfplan && terraform apply tfplan

deploy-application: ## Desplegar solo la aplicación
	@echo -e "$(BLUE)🚀 Desplegando aplicación...$(NC)"
	@if [ ! -f ".env.production" ]; then echo -e "$(RED)Error: .env.production no encontrado. Ejecuta 'make setup-secrets' primero$(NC)"; exit 1; fi
	@source .env.production && \
	gcloud builds submit --tag="$$GCP_REGION-docker.pkg.dev/$$GCP_PROJECT_ID/phishing-detector/phishing-detector:latest" --project=$$GCP_PROJECT_ID . && \
	gcloud run deploy phishing-detector \
		--image="$$GCP_REGION-docker.pkg.dev/$$GCP_PROJECT_ID/phishing-detector/phishing-detector:latest" \
		--platform=managed \
		--region=$$GCP_REGION \
		--allow-unauthenticated \
		--port=8000 \
		--memory=2Gi \
		--cpu=2 \
		--concurrency=100 \
		--max-instances=10 \
		--min-instances=1 \
		--set-secrets=GEMINI_API_KEY=gemini-api-key:latest,API_TOKEN=api-token:latest \
		--set-env-vars=LOG_LEVEL=info,WORKERS=1 \
		--project=$$GCP_PROJECT_ID

deploy-all: ## Desplegar todo el sistema (infraestructura + aplicación)
	@echo -e "$(BLUE)🚀 Desplegando sistema completo...$(NC)"
	@$(SCRIPTS_DIR)/deploy-production.sh

setup-addon: ## Configurar Gmail Add-on
	@echo -e "$(BLUE)📧 Configurando Gmail Add-on...$(NC)"
	@$(SCRIPTS_DIR)/setup-gmail-addon.sh

test-local: ## Ejecutar tests localmente
	@echo -e "$(BLUE)🧪 Ejecutando tests locales...$(NC)"
	pytest tests/ -v --cov=src --cov-report=term-missing

test-production: ## Probar deployment en producción
	@echo -e "$(BLUE)🧪 Probando deployment en producción...$(NC)"
	@if [ ! -f ".env.production" ]; then echo -e "$(RED)Error: .env.production no encontrado$(NC)"; exit 1; fi
	@source .env.production && \
	echo -e "$(YELLOW)Probando health check...$(NC)" && \
	curl -f "$$PHISHING_API_ENDPOINT/health" && \
	echo -e "\n$(GREEN)✅ Health check OK$(NC)" && \
	echo -e "$(YELLOW)Probando readiness...$(NC)" && \
	curl -f "$$PHISHING_API_ENDPOINT/ready" && \
	echo -e "\n$(GREEN)✅ Readiness OK$(NC)" && \
	echo -e "$(YELLOW)Probando API de clasificación...$(NC)" && \
	response=$$(curl -s -H "Authorization: Bearer $$API_TOKEN" \
		-H "Content-Type: application/json" \
		-d '{"raw_headers":"From: test@example.com","text_body":"Test message","raw_html":"<p>Test</p>","attachments_meta":[],"account_context":{"user_locale":"es-ES"}}' \
		"$$PHISHING_API_ENDPOINT/classify") && \
	echo "$$response" | jq -r '.classification' && \
	echo -e "$(GREEN)✅ API test OK$(NC)"

monitoring: ## Abrir dashboards de monitoreo
	@echo -e "$(BLUE)📊 Abriendo dashboards de monitoreo...$(NC)"
	@if [ ! -f ".env.production" ]; then echo -e "$(RED)Error: .env.production no encontrado$(NC)"; exit 1; fi
	@source .env.production && \
	echo -e "$(BLUE)🌐 Cloud Run Console:$(NC)" && \
	echo "https://console.cloud.google.com/run/detail/$$GCP_REGION/phishing-detector/metrics?project=$$GCP_PROJECT_ID" && \
	echo -e "$(BLUE)📊 Cloud Monitoring:$(NC)" && \
	echo "https://console.cloud.google.com/monitoring/dashboards?project=$$GCP_PROJECT_ID" && \
	echo -e "$(BLUE)📋 Logs:$(NC)" && \
	echo "https://console.cloud.google.com/logs/query?project=$$GCP_PROJECT_ID"

logs: ## Ver logs de la aplicación
	@echo -e "$(BLUE)📋 Viendo logs de la aplicación...$(NC)"
	@if [ ! -f ".env.production" ]; then echo -e "$(RED)Error: .env.production no encontrado$(NC)"; exit 1; fi
	@source .env.production && \
	gcloud logs tail "resource.type=cloud_run_revision AND resource.labels.service_name=phishing-detector" \
		--project=$$GCP_PROJECT_ID --format="value(timestamp,textPayload,jsonPayload.message)"

metrics: ## Ver métricas de Prometheus
	@echo -e "$(BLUE)📊 Consultando métricas...$(NC)"
	@if [ ! -f ".env.production" ]; then echo -e "$(RED)Error: .env.production no encontrado$(NC)"; exit 1; fi
	@source .env.production && \
	curl -s "$$PHISHING_API_ENDPOINT/metrics" | grep -E "(phishing_|http_)" | head -20

status: ## Ver estado del sistema
	@echo -e "$(BLUE)📊 Estado del sistema$(NC)"
	@if [ ! -f ".env.production" ]; then echo -e "$(RED)Error: Sistema no desplegado$(NC)"; exit 1; fi
	@source .env.production && \
	echo -e "$(YELLOW)Proyecto GCP:$(NC) $$GCP_PROJECT_ID" && \
	echo -e "$(YELLOW)Región:$(NC) $$GCP_REGION" && \
	echo -e "$(YELLOW)Service URL:$(NC) $$PHISHING_API_ENDPOINT" && \
	echo -e "$(YELLOW)Health Status:$(NC) $$(curl -s "$$PHISHING_API_ENDPOINT/health" | jq -r '.status' 2>/dev/null || echo 'UNAVAILABLE')" && \
	echo -e "$(YELLOW)Ready Status:$(NC) $$(curl -s "$$PHISHING_API_ENDPOINT/ready" | jq -r '.status' 2>/dev/null || echo 'NOT READY')"

rollback: ## Rollback a la versión anterior
	@echo -e "$(BLUE)🔄 Haciendo rollback...$(NC)"
	@if [ ! -f ".env.production" ]; then echo -e "$(RED)Error: .env.production no encontrado$(NC)"; exit 1; fi
	@source .env.production && \
	gcloud run services update-traffic phishing-detector \
		--to-revisions=LATEST=0 \
		--region=$$GCP_REGION \
		--project=$$GCP_PROJECT_ID && \
	echo -e "$(GREEN)✅ Rollback completado$(NC)"

clean: ## Limpiar archivos temporales
	@echo -e "$(BLUE)🧹 Limpiando archivos temporales...$(NC)"
	rm -f .env.production.bak
	rm -f terraform/tfplan
	rm -f terraform/.terraform.lock.hcl
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo -e "$(GREEN)✅ Limpieza completada$(NC)"

destroy: ## DESTRUIR toda la infraestructura (¡PELIGROSO!)
	@echo -e "$(RED)⚠️ ADVERTENCIA: Esto destruirá TODA la infraestructura$(NC)"
	@echo -e "$(YELLOW)¿Estás seguro? Escribe 'destroy-everything' para confirmar:$(NC)"
	@read confirm && [ "$$confirm" = "destroy-everything" ] || (echo "Cancelado" && exit 1)
	@echo -e "$(BLUE)🗑️ Destruyendo infraestructura...$(NC)"
	cd terraform && terraform destroy -auto-approve
	@echo -e "$(GREEN)✅ Infraestructura destruida$(NC)"

# Alias útiles
setup: setup-gcp setup-secrets ## Configuración inicial completa
deploy: deploy-all ## Desplegar (alias para deploy-all)
test: test-production ## Probar producción (alias para test-production)

# Comandos de desarrollo
dev-setup: ## Configurar entorno de desarrollo
	@echo -e "$(BLUE)🛠️ Configurando entorno de desarrollo...$(NC)"
	pip install -e .
	pip install -e ".[dev]"
	pip install black isort flake8 mypy pytest-cov bandit
	pre-commit install
	@echo -e "$(GREEN)✅ Entorno de desarrollo configurado$(NC)"

dev-test: ## Ejecutar tests de desarrollo
	@echo -e "$(BLUE)🧪 Ejecutando tests de desarrollo...$(NC)"
	pytest tests/ -v -x --tb=short
	
dev-run: ## Ejecutar aplicación localmente
	@echo -e "$(BLUE)🏃 Ejecutando aplicación localmente...$(NC)"
	@echo -e "$(YELLOW)Asegúrate de tener GEMINI_API_KEY y API_TOKEN en .env$(NC)"
	uvicorn src.app:app --reload --host 0.0.0.0 --port 8000

# Comandos de formateo y calidad de código
format: ## Formatear código con Black e isort
	@echo -e "$(BLUE)🔧 Formateando código con Black...$(NC)"
	python -m black src/ tests/
	@echo -e "$(BLUE)🔧 Ordenando imports con isort...$(NC)"
	python -m isort src/ tests/
	@echo -e "$(GREEN)✅ Formateo completado$(NC)"

format-check: ## Verificar formato sin modificar archivos (CI)
	@echo -e "$(BLUE)🔍 Verificando formato con Black...$(NC)"
	python -m black --check --diff src/ tests/
	@echo -e "$(BLUE)🔍 Verificando imports con isort...$(NC)"
	python -m isort --check-only --diff src/ tests/
	@echo -e "$(GREEN)✅ Verificación de formato completada$(NC)"

lint: ## Ejecutar linting con flake8 y mypy
	@echo -e "$(BLUE)🔍 Ejecutando flake8...$(NC)"
	python -m flake8 src/ tests/ --max-line-length=88 --extend-ignore=E203,W503
	@echo -e "$(BLUE)🔍 Ejecutando mypy...$(NC)"
	python -m mypy src/ --ignore-missing-imports --strict-optional
	@echo -e "$(GREEN)✅ Linting completado$(NC)"

security-scan: ## Análisis de seguridad con bandit
	@echo -e "$(BLUE)🛡️ Ejecutando análisis de seguridad...$(NC)"
	python -m bandit -r src/ -f txt
	@echo -e "$(GREEN)✅ Análisis de seguridad completado$(NC)"

ci-check: format-check lint test-local security-scan ## Ejecutar todas las verificaciones de CI localmente
	@echo -e "$(GREEN)🎉 Todas las verificaciones de CI pasaron exitosamente$(NC)"

fix: format ## Alias para format (arreglar formateo automáticamente)

# Información del proyecto
info: ## Mostrar información del proyecto
	@echo -e "$(BLUE)📋 Información del Proyecto$(NC)"
	@echo -e "$(YELLOW)Nombre:$(NC) Phishing Detector"
	@echo -e "$(YELLOW)Versión:$(NC) 1.0.0"
	@echo -e "$(YELLOW)Tecnologías:$(NC) FastAPI, Python 3.11, Gemini 2.5, Google Cloud Run"
	@echo -e "$(YELLOW)Repositorio:$(NC) $(shell git remote get-url origin 2>/dev/null || echo 'No configurado')"
	@echo -e "$(YELLOW)Branch actual:$(NC) $(shell git branch --show-current 2>/dev/null || echo 'No disponible')"
	@echo -e "$(YELLOW)Último commit:$(NC) $(shell git log -1 --oneline 2>/dev/null || echo 'No disponible')"