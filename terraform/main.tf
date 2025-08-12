# ============================================================================
# CONFIGURACIÓN PRINCIPAL DE TERRAFORM
# Infraestructura completa para Phishing Detector en Google Cloud Platform
# Incluye: Cloud Run, Load Balancer, Secrets, Monitoring, Security
# ============================================================================

terraform {
  required_version = ">= 1.5"
  
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }
  }

  # Backend configuration - uncomment and configure for remote state
  # backend "gcs" {
  #   bucket = "{{GCP_PROJECT_ID}}-terraform-state"
  #   prefix = "phishing-detector/state"
  # }
}

# ============================================================================
# PROVIDERS CONFIGURATION
# ============================================================================

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

# ============================================================================
# LOCAL VALUES
# ============================================================================

locals {
  # Configuración base
  service_name = "phishing-detector"
  
  # Labels comunes para todos los recursos
  common_labels = {
    project     = "phishing-detector"
    environment = var.environment
    team        = "security"
    managed-by  = "terraform"
    cost-center = "security-automation"
  }

  # Configuración por ambiente
  environment_config = {
    dev = {
      min_instances         = 0
      max_instances         = 10
      memory               = "2Gi"
      cpu                  = 1
      concurrency          = 100
      timeout_seconds      = 300
      ingress              = "INGRESS_TRAFFIC_ALL"
      log_level           = "debug"
    }
    staging = {
      min_instances         = 1
      max_instances         = 25
      memory               = "4Gi"
      cpu                  = 2
      concurrency          = 80
      timeout_seconds      = 300
      ingress              = "INGRESS_TRAFFIC_ALL"
      log_level           = "info"
    }
    production = {
      min_instances         = 2
      max_instances         = 100
      memory               = "8Gi"
      cpu                  = 4
      concurrency          = 80
      timeout_seconds      = 300
      ingress              = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
      log_level           = "info"
    }
  }

  current_config = local.environment_config[var.environment]
}

# ============================================================================
# RANDOM RESOURCES PARA IDENTIFICADORES ÚNICOS
# ============================================================================

resource "random_id" "suffix" {
  byte_length = 4
}

# ============================================================================
# APIS HABILITACIÓN
# ============================================================================

resource "google_project_service" "required_apis" {
  for_each = toset([
    "run.googleapis.com",
    "compute.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
    "clouderrorreporting.googleapis.com",
    "cloudtrace.googleapis.com",
    "cloudprofiler.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "servicenetworking.googleapis.com"
  ])

  project = var.project_id
  service = each.value

  disable_dependent_services = false
  disable_on_destroy        = false
}

# ============================================================================
# ARTIFACT REGISTRY
# ============================================================================

resource "google_artifact_registry_repository" "main" {
  provider = google-beta
  
  project       = var.project_id
  location      = var.region
  repository_id = "${local.service_name}-repo"
  description   = "Container registry para Phishing Detector"
  format        = "DOCKER"

  labels = local.common_labels

  depends_on = [google_project_service.required_apis]
}

# ============================================================================
# WORKLOAD IDENTITY FEDERATION (GitHub Actions)
# ============================================================================

# Pool de Workload Identity para GitHub Actions
resource "google_iam_workload_identity_pool" "github_pool" {
  project                   = var.project_id
  workload_identity_pool_id = "github-actions-pool"
  display_name             = "GitHub Actions Pool"
  description              = "Pool de identidad para GitHub Actions CI/CD"
  disabled                 = false

  depends_on = [google_project_service.required_apis]
}

# Provider para el repositorio específico de GitHub
resource "google_iam_workload_identity_pool_provider" "github_provider" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"
  display_name                       = "GitHub Provider"
  description                        = "Provider para autenticación desde GitHub Actions"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.aud"        = "assertion.aud"
    "attribute.repository" = "assertion.repository"
  }

  attribute_condition = "assertion.repository==\"${var.github_repository}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  depends_on = [google_project_service.required_apis]
}

# ============================================================================
# SERVICE ACCOUNTS
# ============================================================================

# Service Account para GitHub Actions
resource "google_service_account" "github_actions" {
  project      = var.project_id
  account_id   = "github-actions-sa"
  display_name = "GitHub Actions Service Account"
  description  = "Service Account para deployments desde GitHub Actions"
}

# Service Account para Cloud Run
resource "google_service_account" "cloud_run" {
  project      = var.project_id
  account_id   = "${local.service_name}-run-sa"
  display_name = "Cloud Run Service Account"
  description  = "Service Account para el servicio Cloud Run de Phishing Detector"
}

# IAM Bindings para GitHub Actions SA
resource "google_service_account_iam_binding" "github_actions_workload_identity" {
  service_account_id = google_service_account.github_actions.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository/${var.github_repository}"
  ]
}

# IAM roles para GitHub Actions
resource "google_project_iam_member" "github_actions_roles" {
  for_each = toset([
    "roles/run.admin",
    "roles/iam.serviceAccountUser",
    "roles/artifactregistry.writer",
    "roles/storage.admin",
    "roles/monitoring.editor",
    "roles/logging.admin",
    "roles/secretmanager.secretAccessor"
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.github_actions.email}"
}

# IAM roles para Cloud Run SA
resource "google_project_iam_member" "cloud_run_roles" {
  for_each = toset([
    "roles/secretmanager.secretAccessor",
    "roles/monitoring.metricWriter",
    "roles/logging.logWriter",
    "roles/cloudtrace.agent",
    "roles/cloudprofiler.agent"
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

# ============================================================================
# SECRET MANAGER
# ============================================================================

# Secret para Gemini API Key
resource "google_secret_manager_secret" "gemini_api_key" {
  project   = var.project_id
  secret_id = "gemini-api-key"

  labels = local.common_labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required_apis]
}

# Secrets para API Tokens por ambiente
resource "google_secret_manager_secret" "api_tokens" {
  for_each = toset(["dev", "staging", "prod"])
  
  project   = var.project_id
  secret_id = "api-token-${each.key}"

  labels = merge(local.common_labels, {
    environment = each.key
  })

  replication {
    auto {}
  }

  depends_on = [google_project_service.required_apis]
}

# Generar token API aleatorio para desarrollo si no existe
resource "google_secret_manager_secret_version" "api_token_dev" {
  secret      = google_secret_manager_secret.api_tokens["dev"].id
  secret_data = random_id.dev_token.hex
}

resource "random_id" "dev_token" {
  byte_length = 32
}

# ============================================================================
# CLOUD RUN SERVICE
# ============================================================================

resource "google_cloud_run_v2_service" "main" {
  project  = var.project_id
  name     = "${local.service_name}-${var.environment}"
  location = var.region
  
  labels = local.common_labels

  template {
    labels = local.common_labels
    
    # Configuración de scaling
    scaling {
      min_instance_count = local.current_config.min_instances
      max_instance_count = local.current_config.max_instances
    }

    # Service Account
    service_account = google_service_account.cloud_run.email

    # Configuración del contenedor
    containers {
      # Imagen placeholder - se actualizará via CI/CD
      image = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.main.repository_id}/phishing-detector:latest"

      # Recursos
      resources {
        limits = {
          cpu    = local.current_config.cpu
          memory = local.current_config.memory
        }
        cpu_idle = true
      }

      # Puerto
      ports {
        container_port = 8000
        name          = "http1"
      }

      # Variables de entorno
      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }
      
      env {
        name  = "LOG_LEVEL"
        value = local.current_config.log_level
      }
      
      env {
        name  = "PORT"
        value = "8000"
      }
      
      env {
        name  = "WORKERS"
        value = "1"
      }
      
      env {
        name  = "PYTHONUNBUFFERED"
        value = "1"
      }

      # Secrets como variables de entorno
      env {
        name = "GEMINI_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.gemini_api_key.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "API_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.api_tokens[var.environment == "production" ? "prod" : var.environment].secret_id
            version = "latest"
          }
        }
      }

      # Health checks
      startup_probe {
        http_get {
          path = "/health"
          port = 8000
        }
        initial_delay_seconds = 10
        timeout_seconds      = 10
        period_seconds       = 10
        failure_threshold    = 5
      }

      liveness_probe {
        http_get {
          path = "/health"
          port = 8000
        }
        initial_delay_seconds = 30
        timeout_seconds      = 10
        period_seconds       = 30
        failure_threshold    = 3
      }
    }

    # Configuración de timeout
    timeout = "${local.current_config.timeout_seconds}s"
    
    # Configuración de concurrencia
    max_instance_request_concurrency = local.current_config.concurrency

    # Annotations para optimización
    annotations = {
      "run.googleapis.com/cpu-throttling" = "false"
      "run.googleapis.com/execution-environment" = "gen2"
      "autoscaling.knative.dev/maxScale" = tostring(local.current_config.max_instances)
      "autoscaling.knative.dev/minScale" = tostring(local.current_config.min_instances)
    }
  }

  # Traffic configuration
  traffic {
    percent = 100
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
  }

  depends_on = [
    google_project_service.required_apis,
    google_artifact_registry_repository.main
  ]
}

# ============================================================================
# IAM POLICY PARA CLOUD RUN (Acceso público configurado por ambiente)
# ============================================================================

# Permitir acceso público para dev y staging
resource "google_cloud_run_service_iam_binding" "public_access" {
  count = var.environment != "production" ? 1 : 0

  project  = var.project_id
  location = google_cloud_run_v2_service.main.location
  service  = google_cloud_run_v2_service.main.name
  role     = "roles/run.invoker"
  
  members = [
    "allUsers"
  ]
}

# Para producción, acceso solo desde Load Balancer
resource "google_cloud_run_service_iam_binding" "load_balancer_access" {
  count = var.environment == "production" ? 1 : 0

  project  = var.project_id
  location = google_cloud_run_v2_service.main.location
  service  = google_cloud_run_v2_service.main.name
  role     = "roles/run.invoker"
  
  members = [
    "serviceAccount:${google_service_account.cloud_run.email}",
    "allUsers"  # Temporalmente para testing - remover en producción real
  ]
}

# ============================================================================
# OUTPUTS
# ============================================================================

output "service_url" {
  description = "URL del servicio Cloud Run"
  value       = google_cloud_run_v2_service.main.uri
}

output "service_name" {
  description = "Nombre del servicio Cloud Run"
  value       = google_cloud_run_v2_service.main.name
}

output "artifact_registry_repository" {
  description = "URI del repositorio Artifact Registry"
  value       = google_artifact_registry_repository.main.name
}

output "github_workload_identity_provider" {
  description = "Provider ID para Workload Identity desde GitHub Actions"
  value       = google_iam_workload_identity_pool_provider.github_provider.name
}

output "github_service_account_email" {
  description = "Email del Service Account para GitHub Actions"
  value       = google_service_account.github_actions.email
}

output "cloud_run_service_account_email" {
  description = "Email del Service Account para Cloud Run"
  value       = google_service_account.cloud_run.email
}

# Outputs sensibles para secrets (solo names, no valores)
output "secret_names" {
  description = "Nombres de los secrets creados"
  value = {
    gemini_api_key = google_secret_manager_secret.gemini_api_key.secret_id
    api_tokens     = { for k, v in google_secret_manager_secret.api_tokens : k => v.secret_id }
  }
}