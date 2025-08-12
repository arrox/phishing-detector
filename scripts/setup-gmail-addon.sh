#!/bin/bash

# Script para configurar el Gmail Add-on después del deployment
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
echo "║              📧 GMAIL ADD-ON SETUP                       ║"
echo "║          Configuración del Add-on de Gmail               ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar que existe .env.production
if [[ ! -f ".env.production" ]]; then
    echo -e "${RED}❌ No se encontró .env.production. Ejecuta primero deploy-production.sh${NC}"
    exit 1
fi

source .env.production

echo -e "${BLUE}🌐 URL del servicio: $PHISHING_API_ENDPOINT${NC}"
echo -e "${BLUE}🔑 API Token: ${API_TOKEN:0:10}...${NC}"
echo

# Crear versión actualizada del código Apps Script con la URL real
echo -e "${YELLOW}📝 Generando código Apps Script actualizado...${NC}"

# Actualizar la configuración en el archivo
cat > gmail-addon/Code-production.gs << EOF
/**
 * Gmail Add-on para detección de phishing - PRODUCCIÓN
 * Integra con el microservicio de análisis de phishing
 */

// Configuración de PRODUCCIÓN
var CONFIG = {
  API_ENDPOINT: '$PHISHING_API_ENDPOINT/classify',
  API_TOKEN: PropertiesService.getScriptProperties().getProperty('API_TOKEN'),
  TIMEOUT_MS: 10000
};

// Colores para el semáforo
var COLORS = {
  phishing: '#f44336',    // Rojo
  sospechoso: '#ff9800',  // Ámbar  
  seguro: '#4caf50'       // Verde
};

// Iconos para el semáforo
var ICONS = {
  phishing: 'https://cdn-icons-png.flaticon.com/512/753/753345.png',
  sospechoso: 'https://cdn-icons-png.flaticon.com/512/1828/1828843.png',
  seguro: 'https://cdn-icons-png.flaticon.com/512/753/753318.png'
};

/**
 * Función principal del Add-on - se ejecuta cuando se abre un mensaje
 */
function onGmailMessageOpen(e) {
  console.log('Add-on activado para mensaje:', e);
  
  try {
    // Verificar configuración
    if (!CONFIG.API_TOKEN) {
      return createErrorCard('Configuración incompleta', 'Falta configurar el token de API en las propiedades del script');
    }
    
    // Obtener mensaje actual
    var messageId = (e.gmail && e.gmail.messageId) || (e.messageMetadata && e.messageMetadata.messageId);
    if (!messageId) {
      return createErrorCard('Error', 'No se pudo obtener el mensaje');
    }
    
    var message = GmailApp.getMessageById(messageId);
    if (!message) {
      return createErrorCard('Error', 'Mensaje no encontrado');
    }
    
    // Crear tarjeta de análisis
    return createAnalysisCard(message);
    
  } catch (error) {
    console.error('Error en onGmailMessageOpen:', error);
    return createErrorCard('Error interno', error.toString());
  }
}

/**
 * Crear tarjeta de análisis de phishing
 */
function createAnalysisCard(message) {
  try {
    // Extraer datos del mensaje
    var emailData = extractEmailData(message);
    
    // Llamar al API de clasificación
    var classification = callPhishingAPI(emailData);
    
    if (!classification) {
      return createLoadingCard();
    }
    
    // Crear tarjeta con resultado
    return buildResultCard(classification);
    
  } catch (error) {
    console.error('Error creando tarjeta de análisis:', error);
    return createErrorCard('Error de análisis', 'No se pudo analizar el mensaje: ' + error.toString());
  }
}

/**
 * Extraer datos necesarios del mensaje de Gmail
 */
function extractEmailData(message) {
  var thread = message.getThread();
  var rawContent = message.getRawContent();
  
  // Extraer headers
  var headers = extractHeaders(rawContent);
  
  // Obtener contenido
  var htmlBody = message.getBody();
  var plainBody = message.getPlainBody() || convertHtmlToText(htmlBody);
  
  // Obtener adjuntos (solo metadatos)
  var attachments = message.getAttachments().map(function(att) {
    return {
      filename: att.getName(),
      mime: att.getContentType(),
      size: att.getSize(),
      hash: 'sha256:' + Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, att.getBytes())
        .map(function(byte) { return ('0' + (byte & 0xFF).toString(16)).slice(-2); }).join('')
    };
  });
  
  return {
    raw_headers: headers,
    raw_html: htmlBody,
    text_body: plainBody,
    attachments_meta: attachments,
    account_context: {
      user_locale: Session.getActiveUserLocale() || 'es-ES',
      trusted_senders: getTrustedSenders(),
      owned_domains: getOwnedDomains()
    }
  };
}

/**
 * Extraer headers del contenido raw del email
 */
function extractHeaders(rawContent) {
  var headerEndIndex = rawContent.indexOf('\r\n\r\n');
  if (headerEndIndex === -1) {
    return rawContent.substring(0, Math.min(2000, rawContent.length));
  }
  return rawContent.substring(0, headerEndIndex);
}

/**
 * Convertir HTML a texto plano básico
 */
function convertHtmlToText(html) {
  return html
    .replace(/<style[^>]*>.*?<\/style>/gim, '')
    .replace(/<script[^>]*>.*?<\/script>/gim, '')
    .replace(/<[^>]*>/gim, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Obtener lista de remitentes confiables (simplificado)
 */
function getTrustedSenders() {
  return [
    'noreply@paypal.com',
    'security@paypal.com',
    'service@amazon.com',
    'no-reply@accounts.google.com'
  ];
}

/**
 * Obtener dominios propios del usuario
 */
function getOwnedDomains() {
  var userEmail = Session.getActiveUser().getEmail();
  var domain = userEmail.split('@')[1];
  return [domain];
}

/**
 * Llamar al API de clasificación de phishing
 */
function callPhishingAPI(emailData) {
  try {
    var options = {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + CONFIG.API_TOKEN,
        'Content-Type': 'application/json'
      },
      payload: JSON.stringify(emailData),
      muteHttpExceptions: true
    };
    
    console.log('Llamando API de phishing...');
    var response = UrlFetchApp.fetch(CONFIG.API_ENDPOINT, options);
    var responseCode = response.getResponseCode();
    
    if (responseCode !== 200) {
      console.error('Error del API:', responseCode, response.getContentText());
      return null;
    }
    
    var result = JSON.parse(response.getContentText());
    console.log('Clasificación recibida:', result.classification, 'Score:', result.risk_score);
    
    return result;
    
  } catch (error) {
    console.error('Error llamando API:', error);
    return null;
  }
}

/**
 * Construir tarjeta con resultado de análisis
 */
function buildResultCard(classification) {
  var cardBuilder = CardService.newCardBuilder();
  
  // Header con semáforo
  var header = CardService.newCardHeader()
    .setTitle('🛡️ Análisis de Seguridad')
    .setSubtitle('Resultado: ' + getClassificationText(classification.classification))
    .setImageUrl(ICONS[classification.classification])
    .setImageStyle(CardService.ImageStyle.CIRCLE);
  
  cardBuilder.setHeader(header);
  
  // Sección principal con semáforo visual
  var section = CardService.newCardSection();
  
  // Widget de semáforo
  var statusWidget = CardService.newDecoratedText()
    .setTopLabel('Estado de seguridad')
    .setText('<font color="' + COLORS[classification.classification] + '"><b>' + getClassificationText(classification.classification).toUpperCase() + '</b></font>')
    .setBottomLabel('Puntuación de riesgo: ' + classification.risk_score + '/100')
    .setStartIcon(CardService.newIconImage().setIconUrl(ICONS[classification.classification]));
  
  section.addWidget(statusWidget);
  
  // Resumen no técnico
  if (classification.non_technical_summary) {
    var summaryWidget = CardService.newTextParagraph()
      .setText('<b>📋 Resumen:</b><br>' + classification.non_technical_summary);
    section.addWidget(summaryWidget);
  }
  
  // Razones principales
  if (classification.top_reasons && classification.top_reasons.length > 0) {
    var reasonsText = classification.top_reasons
      .map(function(reason, index) { return (index + 1) + '. ' + reason; })
      .join('<br>');
    
    var reasonsWidget = CardService.newTextParagraph()
      .setText('<b>🔍 Razones principales:</b><br>' + reasonsText);
    section.addWidget(reasonsWidget);
  }
  
  // Acciones recomendadas
  if (classification.recommended_actions && classification.recommended_actions.length > 0) {
    var actionsText = classification.recommended_actions
      .map(function(action, index) { return '• ' + action; })
      .join('<br>');
    
    var actionsWidget = CardService.newTextParagraph()
      .setText('<b>🛡️ Acciones recomendadas:</b><br>' + actionsText);
    section.addWidget(actionsWidget);
  }
  
  cardBuilder.addSection(section);
  
  // Sección de detalles técnicos (colapsable)
  var detailsSection = createDetailsSection(classification);
  cardBuilder.addSection(detailsSection);
  
  // Footer con información adicional
  var footerSection = CardService.newCardSection();
  var footerWidget = CardService.newTextParagraph()
    .setText('<i>⚡ Análisis completado en ' + classification.latency_ms + 'ms</i>');
  footerSection.addWidget(footerWidget);
  cardBuilder.addSection(footerSection);
  
  return [cardBuilder.build()];
}

/**
 * Crear sección de detalles técnicos
 */
function createDetailsSection(classification) {
  var section = CardService.newCardSection();
  
  // Botón para mostrar/ocultar detalles
  var showDetailsAction = CardService.newAction()
    .setFunctionName('showTechnicalDetails')
    .setParameters({
      'classification_data': JSON.stringify(classification)
    });
  
  var detailsButton = CardService.newTextButton()
    .setText('🔧 Ver detalles técnicos')
    .setOnClickAction(showDetailsAction);
  
  section.addWidget(detailsButton);
  
  return section;
}

/**
 * Mostrar detalles técnicos en una nueva tarjeta
 */
function showTechnicalDetails(e) {
  try {
    var classificationData = JSON.parse(e.parameters.classification_data);
    
    var cardBuilder = CardService.newCardBuilder();
    
    // Header
    cardBuilder.setHeader(CardService.newCardHeader()
      .setTitle('🔧 Detalles Técnicos')
      .setSubtitle('Análisis detallado de seguridad'));
    
    var section = CardService.newCardSection();
    
    // Hallazgos de headers
    if (classificationData.evidence && classificationData.evidence.header_findings) {
      var headerText = buildHeaderFindingsText(classificationData.evidence.header_findings);
      section.addWidget(CardService.newTextParagraph()
        .setText('<b>📧 Análisis de Headers:</b><br>' + headerText));
    }
    
    // Hallazgos de URLs
    if (classificationData.evidence && classificationData.evidence.url_findings && classificationData.evidence.url_findings.length > 0) {
      var urlsText = classificationData.evidence.url_findings
        .map(function(finding) { return '• ' + finding.url + ': ' + finding.reason; })
        .join('<br>');
      section.addWidget(CardService.newTextParagraph()
        .setText('<b>🔗 URLs Sospechosas:</b><br>' + urlsText));
    }
    
    // Señales NLP
    if (classificationData.evidence && classificationData.evidence.nlp_signals && classificationData.evidence.nlp_signals.length > 0) {
      var nlpText = classificationData.evidence.nlp_signals
        .map(function(signal) { return '• ' + signal; })
        .join('<br>');
      section.addWidget(CardService.newTextParagraph()
        .setText('<b>📝 Análisis de Contenido:</b><br>' + nlpText));
    }
    
    cardBuilder.addSection(section);
    
    // Botón de regreso
    var backAction = CardService.newAction()
      .setFunctionName('onGmailMessageOpen');
    var backButton = CardService.newTextButton()
      .setText('← Volver al resumen')
      .setOnClickAction(backAction);
    
    var footerSection = CardService.newCardSection();
    footerSection.addWidget(backButton);
    cardBuilder.addSection(footerSection);
    
    return CardService.newNavigation().updateCard(cardBuilder.build());
    
  } catch (error) {
    console.error('Error mostrando detalles:', error);
    return createErrorCard('Error', 'No se pudieron cargar los detalles técnicos');
  }
}

/**
 * Construir texto de hallazgos de headers
 */
function buildHeaderFindingsText(headerFindings) {
  var findings = [];
  
  if (headerFindings.spf_dkim_dmarc !== 'ok') {
    findings.push('SPF/DKIM/DMARC: ' + headerFindings.spf_dkim_dmarc);
  }
  
  if (headerFindings.reply_to_mismatch) {
    findings.push('Reply-To no coincide con From');
  }
  
  if (headerFindings.display_name_spoof) {
    findings.push('Posible suplantación en nombre mostrado');
  }
  
  if (headerFindings.punycode_detected) {
    findings.push('Dominios con caracteres especiales detectados');
  }
  
  if (headerFindings.suspicious_received) {
    findings.push('Cadena de enrutamiento sospechosa');
  }
  
  return findings.length > 0 ? findings.join('<br>') : 'Sin problemas detectados';
}

/**
 * Obtener texto amigable para clasificación
 */
function getClassificationText(classification) {
  switch (classification) {
    case 'phishing':
      return 'Peligroso';
    case 'sospechoso':
      return 'Sospechoso';
    case 'seguro':
      return 'Seguro';
    default:
      return 'Desconocido';
  }
}

/**
 * Crear tarjeta de error
 */
function createErrorCard(title, message) {
  var cardBuilder = CardService.newCardBuilder();
  
  var header = CardService.newCardHeader()
    .setTitle('❌ ' + title)
    .setImageUrl('https://cdn-icons-png.flaticon.com/512/753/753345.png')
    .setImageStyle(CardService.ImageStyle.CIRCLE);
  
  cardBuilder.setHeader(header);
  
  var section = CardService.newCardSection();
  var errorWidget = CardService.newTextParagraph()
    .setText(message);
  
  section.addWidget(errorWidget);
  cardBuilder.addSection(section);
  
  return [cardBuilder.build()];
}

/**
 * Crear tarjeta de carga
 */
function createLoadingCard() {
  var cardBuilder = CardService.newCardBuilder();
  
  var header = CardService.newCardHeader()
    .setTitle('⏳ Analizando...')
    .setSubtitle('Por favor espera')
    .setImageUrl('https://cdn-icons-png.flaticon.com/512/1828/1828843.png')
    .setImageStyle(CardService.ImageStyle.CIRCLE);
  
  cardBuilder.setHeader(header);
  
  var section = CardService.newCardSection();
  var loadingWidget = CardService.newTextParagraph()
    .setText('🔍 Analizando el mensaje para detectar amenazas de seguridad...');
  
  section.addWidget(loadingWidget);
  cardBuilder.addSection(section);
  
  return [cardBuilder.build()];
}

/**
 * Función para analizar mensaje actual (acción universal)
 */
function analyzeCurrentMessage(e) {
  return onGmailMessageOpen(e);
}

/**
 * Función de instalación - configurar propiedades
 */
function onInstall(e) {
  console.log('Add-on instalado');
  // Configurar token automáticamente si no existe
  var properties = PropertiesService.getScriptProperties();
  if (!properties.getProperty('API_TOKEN')) {
    // Mostrar mensaje para que el usuario configure el token
    console.log('Configure API_TOKEN en las propiedades del script');
  }
}
EOF

echo -e "${GREEN}✅ Código Apps Script generado: gmail-addon/Code-production.gs${NC}"
echo

# Instrucciones detalladas
echo -e "${BLUE}📋 INSTRUCCIONES PARA CONFIGURAR EL GMAIL ADD-ON:${NC}"
echo
echo -e "${YELLOW}1. Ve a Google Apps Script:${NC}"
echo -e "   https://script.google.com"
echo
echo -e "${YELLOW}2. Crea un nuevo proyecto:${NC}"
echo -e "   • Haz clic en 'Nuevo proyecto'"
echo -e "   • Nombra el proyecto: 'Detector de Phishing'"
echo
echo -e "${YELLOW}3. Configura el manifiesto:${NC}"
echo -e "   • Ve a 'Configuración del proyecto' (⚙️)"
echo -e "   • Marca 'Mostrar archivo de manifiesto appsscript.json'"
echo -e "   • Reemplaza el contenido con el archivo: gmail-addon/appsscript.json"
echo
echo -e "${YELLOW}4. Agrega el código:${NC}"
echo -e "   • Reemplaza el contenido de Code.gs con: gmail-addon/Code-production.gs"
echo
echo -e "${YELLOW}5. Configura el API Token:${NC}"
echo -e "   • Ve a 'Configuración del proyecto' > 'Propiedades del script'"
echo -e "   • Agrega nueva propiedad:"
echo -e "     Clave: API_TOKEN"
echo -e "     Valor: $API_TOKEN"
echo
echo -e "${YELLOW}6. Guarda y despliega:${NC}"
echo -e "   • Ctrl+S para guardar"
echo -e "   • Ve a 'Desplegar' > 'Nueva implementación'"
echo -e "   • Selecciona tipo: 'Add-on'"
echo -e "   • Descripción: 'Detector de phishing para Gmail'"
echo -e "   • Haz clic en 'Desplegar'"
echo
echo -e "${YELLOW}7. Instala en Gmail:${NC}"
echo -e "   • Ve a Gmail"
echo -e "   • Configuración (⚙️) > Ver todas las configuraciones"
echo -e "   • Pestaña 'Complementos'"
echo -e "   • Busca tu add-on y actívalo"
echo

# Crear archivo con la configuración completa
cat > gmail-addon-setup.md << EOF
# Configuración del Gmail Add-on - Detector de Phishing

## Información del servicio
- **URL del API**: $PHISHING_API_ENDPOINT
- **API Token**: $API_TOKEN

## Archivos necesarios
1. \`gmail-addon/appsscript.json\` - Manifiesto del add-on
2. \`gmail-addon/Code-production.gs\` - Código principal (generado automáticamente)

## Configuración en Google Apps Script

### 1. Crear proyecto
1. Ve a https://script.google.com
2. Clic en "Nuevo proyecto"
3. Nombra el proyecto: "Detector de Phishing"

### 2. Configurar manifiesto
1. Ve a "Configuración del proyecto" (⚙️)
2. Marca "Mostrar archivo de manifiesto appsscript.json"
3. Copia el contenido de \`gmail-addon/appsscript.json\`

### 3. Agregar código
1. Reemplaza Code.gs con el contenido de \`gmail-addon/Code-production.gs\`

### 4. Configurar propiedades
1. Ve a "Configuración del proyecto" > "Propiedades del script"
2. Agrega:
   - **Clave**: API_TOKEN
   - **Valor**: $API_TOKEN

### 5. Desplegar
1. Guarda (Ctrl+S)
2. Ve a "Desplegar" > "Nueva implementación"
3. Tipo: "Add-on"
4. Descripción: "Detector de phishing para Gmail"
5. Haz clic en "Desplegar"

### 6. Instalar en Gmail
1. Ve a Gmail
2. Configuración (⚙️) > Ver todas las configuraciones
3. Pestaña "Complementos"
4. Busca y activa tu add-on

## Pruebas
Una vez instalado, el add-on aparecerá automáticamente cuando abras emails en Gmail con:
- 🔴 **PELIGROSO** para phishing
- 🟡 **SOSPECHOSO** para emails dudosos  
- 🟢 **SEGURO** para emails legítimos

## Soporte
- **Logs**: Ve a Google Apps Script > Ejecuciones para ver logs
- **API Health**: $PHISHING_API_ENDPOINT/health
- **Métricas**: Console GCP > Cloud Run > phishing-detector
EOF

echo -e "${GREEN}✅ Documentación guardada en gmail-addon-setup.md${NC}"
echo
echo -e "${PURPLE}🎉 ¡Configuración del Gmail Add-on completada!${NC}"
echo -e "${BLUE}📄 Revisa gmail-addon-setup.md para instrucciones detalladas${NC}"