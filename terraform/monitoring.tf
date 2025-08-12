# ============================================================================
# MONITORING Y OBSERVABILIDAD STACK
# Configuración completa de monitoring para Phishing Detector
# Incluye: Métricas, Alertas, Dashboards, SLOs, Logs
# ============================================================================

# ============================================================================
# NOTIFICATION CHANNELS
# ============================================================================

resource "google_monitoring_notification_channel" "email_alerts" {
  count = var.alert_email != "" ? 1 : 0
  
  project      = var.project_id
  display_name = "Email Alerts - Phishing Detector"
  type         = "email"
  
  labels = {
    email_address = var.alert_email
  }
  
  enabled = true
}

resource "google_monitoring_notification_channel" "slack_alerts" {
  count = var.environment == "production" ? 1 : 0
  
  project      = var.project_id
  display_name = "Slack Alerts - Production"
  type         = "slack"
  
  # Configurar con webhook de Slack
  labels = {
    channel_name = "#alerts-phishing-detector"
    url          = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
  }
  
  enabled = true
}

# ============================================================================
# UPTIME CHECKS
# ============================================================================

resource "google_monitoring_uptime_check_config" "health_check" {
  project      = var.project_id
  display_name = "Health Check - ${local.service_name}-${var.environment}"
  timeout      = "10s"
  period       = "60s"

  http_check {
    path         = "/health"
    port         = 443
    use_ssl      = true
    validate_ssl = true
    
    accepted_response_status_codes {
      status_class = "STATUS_CLASS_2XX"
    }
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = replace(google_cloud_run_v2_service.main.uri, "https://", "")
    }
  }

  content_matchers {
    content = "healthy"
    matcher = "CONTAINS_STRING"
  }

  checker_type = "STATIC_IP_CHECKERS"
}

resource "google_monitoring_uptime_check_config" "api_check" {
  project      = var.project_id
  display_name = "API Readiness - ${local.service_name}-${var.environment}"
  timeout      = "10s"
  period       = "300s"  # Cada 5 minutos para no saturar

  http_check {
    path         = "/ready"
    port         = 443
    use_ssl      = true
    validate_ssl = true
    
    accepted_response_status_codes {
      status_class = "STATUS_CLASS_2XX"
    }
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = replace(google_cloud_run_v2_service.main.uri, "https://", "")
    }
  }

  content_matchers {
    content = "ready"
    matcher = "CONTAINS_STRING"
  }

  checker_type = "STATIC_IP_CHECKERS"
}

# ============================================================================
# ALERTING POLICIES
# ============================================================================

# Alert: Servicio no disponible
resource "google_monitoring_alert_policy" "service_down" {
  project      = var.project_id
  display_name = "Service Down - ${local.service_name}-${var.environment}"
  
  documentation {
    content = <<-EOT
    # Servicio Phishing Detector No Disponible
    
    ## Descripción
    El servicio de detección de phishing no está respondiendo a health checks.
    
    ## Impacto
    - Los usuarios no pueden usar la funcionalidad de detección
    - Gmail Add-on no funcionará correctamente
    - Posible pérdida de revenue/productividad
    
    ## Acciones Inmediatas
    1. Verificar logs del servicio Cloud Run
    2. Revisar métricas de recursos (CPU, memoria)
    3. Verificar conectividad con Gemini API
    4. Ejecutar rollback si es necesario
    
    ## Runbook
    https://wiki.company.com/runbooks/phishing-detector-down
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Uptime check failed"
    
    condition_threshold {
      filter = "resource.type=\"uptime_url\" AND metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\""
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_FRACTION_TRUE"
      }
      
      comparison      = "COMPARISON_LESS_THAN"
      threshold_value = 0.8  # 80% success rate
      duration        = "300s"  # Durante 5 minutos
      
      trigger {
        count = 1
      }
    }
  }

  notification_channels = var.alert_email != "" ? [google_monitoring_notification_channel.email_alerts[0].name] : []
  
  alert_strategy {
    auto_close = "604800s"  # 7 días
    
    notification_rate_limit {
      period = "300s"  # No más de 1 alerta cada 5 minutos
    }
  }
  
  severity = "CRITICAL"
  enabled  = true
}

# Alert: Alta latencia
resource "google_monitoring_alert_policy" "high_latency" {
  project      = var.project_id
  display_name = "High Latency - ${local.service_name}-${var.environment}"
  
  documentation {
    content = <<-EOT
    # Alta Latencia Detectada
    
    ## Descripción
    La latencia del servicio de phishing detection está por encima del SLO.
    
    ## Umbrales
    - **Warning**: >2 segundos (P95)
    - **Critical**: >5 segundos (P95)
    
    ## Posibles Causas
    - Sobrecarga del servicio
    - Problemas con Gemini API
    - Problemas de red
    - Recursos insuficientes (CPU/memoria)
    
    ## Investigación
    1. Revisar dashboard de latencia
    2. Verificar métricas de recursos
    3. Analizar logs de errores
    4. Revisar traces distribuidos
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Request latency P95 > threshold"
    
    condition_threshold {
      filter = "resource.type=\"cloud_run_revision\" AND metric.type=\"run.googleapis.com/request_latencies\""
      
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_DELTA"
        cross_series_reducer = "REDUCE_PERCENTILE_95"
        
        group_by_fields = [
          "resource.labels.service_name"
        ]
      }
      
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = var.slo_latency_threshold
      duration        = "300s"
      
      trigger {
        count = 1
      }
    }
  }

  notification_channels = var.alert_email != "" ? [google_monitoring_notification_channel.email_alerts[0].name] : []
  
  alert_strategy {
    auto_close = "86400s"  # 24 horas
  }
  
  severity = "WARNING"
  enabled  = true
}

# Alert: Tasa alta de errores
resource "google_monitoring_alert_policy" "high_error_rate" {
  project      = var.project_id
  display_name = "High Error Rate - ${local.service_name}-${var.environment}"
  
  documentation {
    content = <<-EOT
    # Tasa Alta de Errores
    
    ## Descripción
    El servicio está devolviendo una tasa alta de errores HTTP 5xx.
    
    ## Umbrales
    - **Warning**: >5% de errores
    - **Critical**: >10% de errores
    
    ## Investigación
    1. Revisar logs de errores recientes
    2. Verificar disponibilidad de Gemini API
    3. Revisar configuración de secrets
    4. Analizar patrones de requests
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Error rate > 5%"
    
    condition_threshold {
      filter = "resource.type=\"cloud_run_revision\" AND metric.type=\"run.googleapis.com/request_count\""
      
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        
        group_by_fields = [
          "resource.labels.service_name",
          "metric.labels.response_code_class"
        ]
      }
      
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 0.05  # 5%
      duration        = "180s"
      
      trigger {
        count = 1
      }
    }
  }

  notification_channels = var.alert_email != "" ? [google_monitoring_notification_channel.email_alerts[0].name] : []
  
  severity = "WARNING"
  enabled  = true
}

# Alert: Uso alto de CPU
resource "google_monitoring_alert_policy" "high_cpu" {
  project      = var.project_id
  display_name = "High CPU Usage - ${local.service_name}-${var.environment}"

  conditions {
    display_name = "CPU utilization > 80%"
    
    condition_threshold {
      filter = "resource.type=\"cloud_run_revision\" AND metric.type=\"run.googleapis.com/container/cpu/utilizations\""
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_MEAN"
      }
      
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 0.8
      duration        = "600s"  # 10 minutos
    }
  }

  notification_channels = var.alert_email != "" ? [google_monitoring_notification_channel.email_alerts[0].name] : []
  severity             = "WARNING"
  enabled              = true
}

# Alert: Uso alto de memoria
resource "google_monitoring_alert_policy" "high_memory" {
  project      = var.project_id
  display_name = "High Memory Usage - ${local.service_name}-${var.environment}"

  conditions {
    display_name = "Memory utilization > 85%"
    
    condition_threshold {
      filter = "resource.type=\"cloud_run_revision\" AND metric.type=\"run.googleapis.com/container/memory/utilizations\""
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_MEAN"
      }
      
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 0.85
      duration        = "600s"
    }
  }

  notification_channels = var.alert_email != "" ? [google_monitoring_notification_channel.email_alerts[0].name] : []
  severity             = "WARNING"
  enabled              = true
}

# ============================================================================
# SLO (SERVICE LEVEL OBJECTIVES)
# ============================================================================

resource "google_monitoring_slo" "availability_slo" {
  project      = var.project_id
  display_name = "Availability SLO - ${local.service_name}-${var.environment}"
  
  service = google_monitoring_service.phishing_detector.name
  
  slo_id = "availability-slo-${var.environment}"

  # SLO: 99.5% availability over 30 days
  goal                = var.slo_availability_threshold / 100
  calendar_period     = "MONTH"
  display_name       = "99.5% Availability"

  availability {
    # Considera successful todas las respuestas no-5xx
    enabled = true
  }
}

resource "google_monitoring_slo" "latency_slo" {
  project      = var.project_id
  display_name = "Latency SLO - ${local.service_name}-${var.environment}"
  
  service = google_monitoring_service.phishing_detector.name
  
  slo_id = "latency-slo-${var.environment}"

  # SLO: 95% of requests < 2 seconds over 30 days
  goal                = 0.95
  calendar_period     = "MONTH"
  display_name       = "95% < 2s Latency"

  request_based {
    distribution_cut {
      distribution_filter = "resource.type=\"cloud_run_revision\" AND metric.type=\"run.googleapis.com/request_latencies\""
      
      range {
        max = var.slo_latency_threshold / 1000  # Convert to seconds
      }
    }
  }
}

# ============================================================================
# CUSTOM METRICS BASADAS EN LOGS
# ============================================================================

resource "google_logging_metric" "phishing_classifications" {
  project = var.project_id
  name    = "phishing_classifications_by_result"
  
  description = "Número de clasificaciones por tipo de resultado"
  
  filter = <<-EOT
    resource.type="cloud_run_revision"
    resource.labels.service_name="${google_cloud_run_v2_service.main.name}"
    jsonPayload.event="Classification completed"
  EOT

  label_extractors = {
    classification = "EXTRACT(jsonPayload.classification)"
    risk_level    = "IF(jsonPayload.risk_score > 0.8, \"high\", IF(jsonPayload.risk_score > 0.5, \"medium\", \"low\"))"
  }

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    display_name = "Phishing Classifications by Result"
  }
}

resource "google_logging_metric" "api_errors" {
  project = var.project_id
  name    = "phishing_api_errors"
  
  description = "Errores de API por tipo"
  
  filter = <<-EOT
    resource.type="cloud_run_revision"
    resource.labels.service_name="${google_cloud_run_v2_service.main.name}"
    severity>=ERROR
  EOT

  label_extractors = {
    error_type = "EXTRACT(jsonPayload.error_type)"
    status_code = "EXTRACT(httpRequest.status)"
  }

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    display_name = "API Errors by Type"
  }
}

# ============================================================================
# MONITORING SERVICE DEFINITION
# ============================================================================

resource "google_monitoring_service" "phishing_detector" {
  project      = var.project_id
  display_name = "Phishing Detector - ${var.environment}"
  service_id   = "${local.service_name}-${var.environment}"

  # Telemetry configuration
  telemetry {
    resource_name = google_cloud_run_v2_service.main.id
  }
}

# ============================================================================
# LOG-BASED ALERTS
# ============================================================================

resource "google_monitoring_alert_policy" "security_alerts" {
  project      = var.project_id
  display_name = "Security Alerts - ${local.service_name}-${var.environment}"
  
  documentation {
    content = <<-EOT
    # Alerta de Seguridad
    
    ## Descripción
    Se detectaron eventos de seguridad sospechosos en el servicio.
    
    ## Eventos Monitoreados
    - Múltiples intentos de autenticación fallidos
    - Requests con payloads maliciosos
    - Acceso no autorizado a endpoints
    
    ## Acción Requerida
    1. Revisar logs de seguridad
    2. Identificar origen de requests sospechosos
    3. Considerar bloqueo temporal
    4. Reportar a equipo de seguridad
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Suspicious authentication failures"
    
    condition_threshold {
      filter = <<-EOT
        resource.type="cloud_run_revision"
        resource.labels.service_name="${google_cloud_run_v2_service.main.name}"
        (jsonPayload.message:"authentication" OR jsonPayload.message:"unauthorized" OR httpRequest.status=401)
      EOT
      
      aggregations {
        alignment_period   = "300s"  # 5 minutos
        per_series_aligner = "ALIGN_RATE"
      }
      
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 10  # Más de 10 fallos por segundo
      duration        = "300s"
    }
  }

  notification_channels = var.alert_email != "" ? [google_monitoring_notification_channel.email_alerts[0].name] : []
  severity             = "CRITICAL"
  enabled              = true
}

# ============================================================================
# OUTPUTS PARA MONITORING
# ============================================================================

output "monitoring_dashboard_url" {
  description = "URL del dashboard de monitoring"
  value       = "https://console.cloud.google.com/monitoring/services/${google_monitoring_service.phishing_detector.service_id}?project=${var.project_id}"
}

output "uptime_check_ids" {
  description = "IDs de los uptime checks creados"
  value = {
    health_check = google_monitoring_uptime_check_config.health_check.uptime_check_id
    api_check    = google_monitoring_uptime_check_config.api_check.uptime_check_id
  }
}

output "slo_names" {
  description = "Nombres de los SLOs creados"
  value = {
    availability = google_monitoring_slo.availability_slo.name
    latency      = google_monitoring_slo.latency_slo.name
  }
}