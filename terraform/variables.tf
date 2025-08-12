# ============================================================================
# VARIABLES DE CONFIGURACIÓN PARA TERRAFORM
# Definiciones de variables para infraestructura Phishing Detector
# ============================================================================

variable "project_id" {
  description = "ID del proyecto de Google Cloud Platform"
  type        = string
  validation {
    condition     = length(var.project_id) > 0
    error_message = "El project_id no puede estar vacío."
  }
}

variable "region" {
  description = "Región de GCP donde desplegar los recursos"
  type        = string
  default     = "us-central1"
  
  validation {
    condition = can(regex("^[a-z]+-[a-z]+[0-9]$", var.region))
    error_message = "La región debe tener el formato correcto (ej: us-central1)."
  }
}

variable "environment" {
  description = "Ambiente de deployment (dev, staging, production)"
  type        = string
  default     = "dev"
  
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "El ambiente debe ser: dev, staging, o production."
  }
}

variable "github_repository" {
  description = "Repositorio de GitHub en formato owner/repo"
  type        = string
  default     = "your-org/phishing-detector"
  
  validation {
    condition     = can(regex("^[^/]+/[^/]+$", var.github_repository))
    error_message = "El repositorio debe tener el formato owner/repo."
  }
}

# ============================================================================
# VARIABLES DE CONFIGURACIÓN AVANZADA
# ============================================================================

variable "enable_monitoring" {
  description = "Habilitar stack completo de monitoring y observabilidad"
  type        = bool
  default     = true
}

variable "enable_load_balancer" {
  description = "Habilitar Load Balancer global (solo para production)"
  type        = bool
  default     = false
}

variable "enable_cdn" {
  description = "Habilitar Cloud CDN (solo para production con Load Balancer)"
  type        = bool
  default     = false
}

variable "enable_waf" {
  description = "Habilitar Cloud Armor WAF (solo para production)"
  type        = bool
  default     = false
}

variable "custom_domain" {
  description = "Dominio personalizado para el servicio (opcional)"
  type        = string
  default     = ""
}

variable "ssl_certificate_name" {
  description = "Nombre del certificado SSL gestionado (requerido para custom_domain)"
  type        = string
  default     = ""
}

# ============================================================================
# VARIABLES DE CONFIGURACIÓN DE RECURSOS
# ============================================================================

variable "min_instances_override" {
  description = "Override para número mínimo de instancias (opcional)"
  type        = number
  default     = null
  
  validation {
    condition     = var.min_instances_override == null || var.min_instances_override >= 0
    error_message = "min_instances_override debe ser >= 0."
  }
}

variable "max_instances_override" {
  description = "Override para número máximo de instancias (opcional)"
  type        = number
  default     = null
  
  validation {
    condition     = var.max_instances_override == null || var.max_instances_override >= 1
    error_message = "max_instances_override debe ser >= 1."
  }
}

variable "memory_override" {
  description = "Override para memoria del contenedor (ej: 2Gi, 4Gi, 8Gi)"
  type        = string
  default     = ""
  
  validation {
    condition = var.memory_override == "" || can(regex("^[0-9]+[GM]i$", var.memory_override))
    error_message = "memory_override debe tener formato válido (ej: 2Gi, 4Gi)."
  }
}

variable "cpu_override" {
  description = "Override para CPU del contenedor (1, 2, 4, etc)"
  type        = number
  default     = null
  
  validation {
    condition     = var.cpu_override == null || var.cpu_override >= 1
    error_message = "cpu_override debe ser >= 1."
  }
}

# ============================================================================
# VARIABLES DE CONFIGURACIÓN DE SEGURIDAD
# ============================================================================

variable "allowed_origins" {
  description = "Lista de orígenes permitidos para CORS"
  type        = list(string)
  default     = ["https://*.googleapis.com", "https://*.google.com"]
}

variable "allowed_hosts" {
  description = "Lista de hosts permitidos para el servicio"
  type        = list(string)
  default     = ["*"]
}

variable "api_rate_limit" {
  description = "Límite de rate limiting para la API (requests por minuto)"
  type        = number
  default     = 1000
  
  validation {
    condition     = var.api_rate_limit > 0
    error_message = "api_rate_limit debe ser > 0."
  }
}

# ============================================================================
# VARIABLES DE CONFIGURACIÓN DE MONITOREO
# ============================================================================

variable "alert_email" {
  description = "Email para recibir alertas de monitoreo"
  type        = string
  default     = ""
  
  validation {
    condition = var.alert_email == "" || can(regex("^[^@]+@[^@]+\\.[^@]+$", var.alert_email))
    error_message = "alert_email debe ser una dirección de email válida."
  }
}

variable "slo_latency_threshold" {
  description = "Umbral de latencia para SLO (en milliseconds)"
  type        = number
  default     = 2000
  
  validation {
    condition     = var.slo_latency_threshold > 0
    error_message = "slo_latency_threshold debe ser > 0."
  }
}

variable "slo_availability_threshold" {
  description = "Umbral de disponibilidad para SLO (percentage, 0-100)"
  type        = number
  default     = 99.5
  
  validation {
    condition     = var.slo_availability_threshold >= 90 && var.slo_availability_threshold <= 100
    error_message = "slo_availability_threshold debe estar entre 90 y 100."
  }
}

variable "retention_days" {
  description = "Días de retención para logs y métricas"
  type        = number
  default     = 30
  
  validation {
    condition     = var.retention_days >= 1 && var.retention_days <= 3653
    error_message = "retention_days debe estar entre 1 y 3653."
  }
}

# ============================================================================
# VARIABLES DE CONFIGURACIÓN DE BACKUP Y DISASTER RECOVERY
# ============================================================================

variable "enable_backup" {
  description = "Habilitar backup automático de configuración"
  type        = bool
  default     = true
}

variable "backup_schedule" {
  description = "Schedule para backups automáticos (cron format)"
  type        = string
  default     = "0 2 * * *"  # Diario a las 2 AM
}

variable "enable_multi_region" {
  description = "Habilitar deployment multi-región para alta disponibilidad"
  type        = bool
  default     = false
}

variable "secondary_region" {
  description = "Región secundaria para multi-región deployment"
  type        = string
  default     = "us-east1"
  
  validation {
    condition = can(regex("^[a-z]+-[a-z]+[0-9]$", var.secondary_region))
    error_message = "La secondary_region debe tener el formato correcto (ej: us-east1)."
  }
}

# ============================================================================
# VARIABLES DE ETIQUETAS Y METADATOS
# ============================================================================

variable "additional_labels" {
  description = "Etiquetas adicionales para todos los recursos"
  type        = map(string)
  default     = {}
}

variable "cost_center" {
  description = "Centro de costo para billing y tracking"
  type        = string
  default     = "security-automation"
}

variable "team" {
  description = "Equipo responsable del proyecto"
  type        = string
  default     = "security"
}

variable "contact_email" {
  description = "Email de contacto del equipo responsable"
  type        = string
  default     = "security@company.com"
  
  validation {
    condition = can(regex("^[^@]+@[^@]+\\.[^@]+$", var.contact_email))
    error_message = "contact_email debe ser una dirección de email válida."
  }
}