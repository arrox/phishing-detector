/**
 * Gmail Add-on para detección de phishing - VERSIÓN FINAL
 * Con Claude Sonnet 4, respuestas humanizadas y UI mejorada
 */

// Configuración
const CONFIG = {
  API_ENDPOINT: 'https://phishing-detector-987579702778.us-central1.run.app/analyze/gmail',
  API_TOKEN: PropertiesService.getScriptProperties().getProperty('API_TOKEN') || 'test-token-123',
  TIMEOUT_MS: 35000
};

// Colores y estilos premium
const COLORS = {
  phishing: '#dc2626',      // Rojo intenso
  suspicious: '#f59e0b',    // Ámbar vibrante  
  safe: '#10b981',          // Verde esmeralda
  neutral: '#6b7280'        // Gris neutro
};

// Iconos específicos por clasificación
const ICONS = {
  // Iconos para cada estado
  phishing: 'https://cdn-icons-png.flaticon.com/512/594/594864.png',      // Escudo rojo con X
  suspicious: 'https://cdn-icons-png.flaticon.com/512/1828/1828395.png', // Escudo amarillo con !
  safe: 'https://cdn-icons-png.flaticon.com/512/4621/4621636.png',       // Escudo verde con ✓
  
  // Iconos generales
  loading: 'https://cdn-icons-png.flaticon.com/512/3406/3406886.png',    // Brain AI
  analyze: 'https://cdn-icons-png.flaticon.com/512/3064/3064197.png',    // Security scan
  setup: 'https://cdn-icons-png.flaticon.com/512/2040/2040946.png'       // Settings
};

// Emojis para mejor UX
const EMOJIS = {
  phishing: '🚨',
  suspicious: '⚠️',
  safe: '✅',
  brain: '🧠',
  shield: '🛡️',
  scan: '🔍'
};

/**
 * Función principal del Add-on
 */
function onGmailMessageOpen(e) {
  console.log('🛡️ Detector de Phishing iniciado');
  
  try {
    // Verificar configuración
    if (!CONFIG.API_TOKEN || CONFIG.API_TOKEN === 'your-api-token-here') {
      return createSetupCard();
    }
    
    // Obtener mensaje actual
    const messageId = (e.gmail && e.gmail.messageId) || (e.messageMetadata && e.messageMetadata.messageId);
    if (!messageId) {
      return createErrorCard('Sin mensaje', 'No se pudo acceder al mensaje actual');
    }
    
    const message = GmailApp.getMessageById(messageId);
    if (!message) {
      return createErrorCard('Mensaje no encontrado', 'El mensaje no está disponible');
    }
    
    // Crear tarjeta principal
    return createMainCard(message, messageId);
    
  } catch (error) {
    console.error('❌ Error:', error);
    return createErrorCard('Error interno', error.toString());
  }
}

/**
 * Crear tarjeta principal con diseño mejorado
 */
function createMainCard(message, messageId) {
  const cardBuilder = CardService.newCardBuilder();
  
  // Header principal
  const header = CardService.newCardHeader()
    .setTitle(`${EMOJIS.shield} Detector de Phishing`)
    .setSubtitle('Análisis avanzado de seguridad')
    .setImageUrl(ICONS.analyze)
    .setImageStyle(CardService.ImageStyle.CIRCLE);
  
  cardBuilder.setHeader(header);
  
  // Sección de información del mensaje
  const messageSection = CardService.newCardSection();
  messageSection.setHeader(`${EMOJIS.scan} Mensaje a Analizar`);
  
  const messageInfo = CardService.newDecoratedText()
    .setTopLabel('ASUNTO')
    .setText(`<b>${message.getSubject()}</b>`)
    .setBottomLabel(`DE: ${message.getFrom()}`)
    .setWrapText(true)
    .setStartIcon(CardService.newIconImage().setIconUrl('https://cdn-icons-png.flaticon.com/512/732/732200.png'));
  
  messageSection.addWidget(messageInfo);
  
  // Información adicional del mensaje
  const messageStats = CardService.newKeyValue()
    .setTopLabel('DETALLES')
    .setContent(`📅 ${message.getDate().toLocaleDateString()} • 📧 ${message.getThread().getMessageCount()} mensajes`)
    .setBottomLabel(`📎 ${message.getAttachments().length} adjuntos`);
  
  messageSection.addWidget(messageStats);
  cardBuilder.addSection(messageSection);
  
  // Sección de análisis
  const analysisSection = CardService.newCardSection();
  analysisSection.setHeader(`${EMOJIS.brain} Análisis Inteligente`);
  
  const analysisDescription = CardService.newTextParagraph()
    .setText(`<b>🎯 Qué analizamos:</b><br>• ${EMOJIS.shield} Autenticidad del remitente<br>• 🔗 Enlaces maliciosos<br>• 📝 Contenido sospechoso<br>• 📎 Adjuntos peligrosos<br>• 🧠 Patrones de phishing`);
  
  analysisSection.addWidget(analysisDescription);
  
  // Botón principal de análisis
  const analyzeAction = CardService.newAction()
    .setFunctionName('performAnalysis')
    .setParameters({'messageId': messageId});
  
  const analyzeButton = CardService.newTextButton()
    .setText(`${EMOJIS.scan} Analizar con IA Avanzada`)
    .setOnClickAction(analyzeAction)
    .setTextButtonStyle(CardService.TextButtonStyle.FILLED);
  
  analysisSection.addWidget(analyzeButton);
  
  // Información de tiempo
  const timeInfo = CardService.newTextParagraph()
    .setText(`<i>⏱️ Tiempo estimado: 10-30 segundos<br>${EMOJIS.brain} IA realizará análisis profundo</i>`);
  
  analysisSection.addWidget(timeInfo);
  cardBuilder.addSection(analysisSection);
  
  return [cardBuilder.build()];
}

/**
 * Realizar análisis con IA
 */
function performAnalysis(e) {
  console.log('🧠 Iniciando análisis con IA...');
  
  try {
    const messageId = e.parameters.messageId;
    const message = GmailApp.getMessageById(messageId);
    
    if (!message) {
      return CardService.newNavigation()
        .updateCard(createErrorCard('Mensaje perdido', 'No se pudo acceder al mensaje'));
    }
    
    // Extraer datos del mensaje
    const emailData = extractEmailData(message);
    
    // Llamar al API
    console.log('🌐 Conectando con IA...');
    const classification = callAnalysisAPI(emailData);
    
    if (!classification) {
      return CardService.newNavigation()
        .updateCard(createErrorCard('Sin respuesta', 'El servicio no respondió. Intenta nuevamente.'));
    }
    
    console.log('✅ Análisis completado:', classification.classification);
    
    // Crear tarjeta de resultado
    const resultCard = buildResultCard(classification, message);
    return CardService.newNavigation().updateCard(resultCard);
    
  } catch (error) {
    console.error('❌ Error en análisis:', error);
    return CardService.newNavigation()
      .updateCard(createErrorCard('Error de análisis', getErrorMessage(error)));
  }
}

/**
 * Extraer datos del mensaje
 */
function extractEmailData(message) {
  const sender = message.getFrom();
  const subject = message.getSubject();
  const body = message.getPlainBody() || message.getBody();
  
  // Headers básicos
  const headers = `From: ${sender}\nSubject: ${subject}\nDate: ${message.getDate()}`;
  
  // Adjuntos
  const attachments = message.getAttachments().map(att => ({
    filename: att.getName(),
    mime: att.getContentType(),
    size: att.getSize()
  }));
  
  return {
    email_headers: headers,
    email_body: body.substring(0, 2000),
    sender: sender,
    subject: subject,
    attachments: attachments
  };
}

/**
 * Llamada al API con manejo robusto
 */
function callAnalysisAPI(emailData) {
  try {
    // Verificar configuración
    if (!CONFIG.API_TOKEN || CONFIG.API_TOKEN === 'your-api-token-here') {
      throw new Error('Token de API no configurado. Configúralo en Propiedades del Script.');
    }
    
    const options = {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + CONFIG.API_TOKEN,
        'Content-Type': 'application/json'
      },
      payload: JSON.stringify(emailData),
      muteHttpExceptions: true
    };
    
    console.log('📡 Enviando a IA...');
    const response = UrlFetchApp.fetch(CONFIG.API_ENDPOINT, options);
    const responseCode = response.getResponseCode();
    const responseText = response.getContentText();
    
    if (responseCode !== 200) {
      console.error(`❌ HTTP ${responseCode}:`, responseText);
      throw new Error(`Error del servidor: ${responseCode}`);
    }
    
    const result = JSON.parse(responseText);
    console.log(`🎯 Resultado: ${result.classification} (${result.risk_score}/100)`);
    
    return result;
    
  } catch (error) {
    console.error('❌ Error API:', error);
    throw error;
  }
}

/**
 * Crear tarjeta de resultado con encabezado dinámico
 */
function buildResultCard(classification, message) {
  const cardBuilder = CardService.newCardBuilder();
  
  // Mapear clasificación
  const riskLevel = mapRiskLevel(classification.classification);
  const riskData = getRiskData(riskLevel);
  
  // Header dinámico basado en resultado - IMAGEN CAMBIA SEGÚN CLASIFICACIÓN
  const header = CardService.newCardHeader()
    .setTitle(`${riskData.emoji} Análisis Completado`)
    .setSubtitle(`Estado: ${riskData.text}`)
    .setImageUrl(riskData.icon)  // ← AQUÍ cambia la imagen según el resultado
    .setImageStyle(CardService.ImageStyle.CIRCLE);
  
  cardBuilder.setHeader(header);
  
  // Sección de resultado principal
  const resultSection = CardService.newCardSection();
  resultSection.setHeader(`${EMOJIS.shield} Resultado de Seguridad`);
  
  // Widget principal de resultado con colores
  const riskWidget = CardService.newDecoratedText()
    .setTopLabel('NIVEL DE RIESGO')
    .setText(`<font color="${riskData.color}"><b>${riskData.text.toUpperCase()}</b></font>`)
    .setBottomLabel(`Puntuación: ${classification.risk_score}/100`)
    .setStartIcon(CardService.newIconImage().setIconUrl(riskData.icon))
    .setWrapText(true);
  
  resultSection.addWidget(riskWidget);
  
  // Barra de progreso visual del riesgo
  const riskBar = createRiskProgressBar(classification.risk_score);
  resultSection.addWidget(riskBar);
  
  cardBuilder.addSection(resultSection);
  
  // Sección de análisis humanizado
  if (classification.analysis) {
    const analysisSection = CardService.newCardSection();
    analysisSection.setHeader(`${EMOJIS.brain} Análisis del Experto`);
    
    const analysisText = CardService.newTextParagraph()
      .setText(formatAnalysisText(classification.analysis));
    
    analysisSection.addWidget(analysisText);
    cardBuilder.addSection(analysisSection);
  }
  
  // Sección de recomendaciones específicas
  if (classification.recommendations && classification.recommendations.length > 0) {
    const recommendationsSection = CardService.newCardSection();
    recommendationsSection.setHeader(`🛡️ Acciones Recomendadas`);
    
    const recommendationsText = classification.recommendations
      .map((rec, index) => `${index + 1}. ${rec}`)
      .join('\n');
    
    const recommendationsWidget = CardService.newTextParagraph()
      .setText(`<b>📋 Sigue estas recomendaciones:</b>\n${recommendationsText}`);
    
    recommendationsSection.addWidget(recommendationsWidget);
    cardBuilder.addSection(recommendationsSection);
  }
  
  // Botón para nuevo análisis
  const actionSection = CardService.newCardSection();
  
  const newAnalysisAction = CardService.newAction()
    .setFunctionName('onGmailMessageOpen');
  
  const newAnalysisButton = CardService.newTextButton()
    .setText(`🔄 Analizar Otro Mensaje`)
    .setOnClickAction(newAnalysisAction);
  
  actionSection.addWidget(newAnalysisButton);
  cardBuilder.addSection(actionSection);
  
  return cardBuilder.build();
}

/**
 * Crear barra de progreso visual para el riesgo
 */
function createRiskProgressBar(riskScore) {
  let barEmoji = '';
  let barColor = '';
  
  if (riskScore <= 30) {
    barEmoji = '🟢🟢🟢⚪⚪';
    barColor = COLORS.safe;
  } else if (riskScore <= 60) {
    barEmoji = '🟡🟡🟡🟡⚪';
    barColor = COLORS.suspicious;
  } else {
    barEmoji = '🔴🔴🔴🔴🔴';
    barColor = COLORS.phishing;
  }
  
  return CardService.newKeyValue()
    .setTopLabel('MEDIDOR DE RIESGO')
    .setContent(`${barEmoji} ${riskScore}%`)
    .setBottomLabel(getRiskDescription(riskScore));
}

/**
 * Funciones de utilidad para el diseño
 */
function mapRiskLevel(classification) {
  switch (classification.toLowerCase()) {
    case 'phishing':
    case 'malicious':
      return 'phishing';
    case 'suspicious':
    case 'sospechoso':
      return 'suspicious';
    case 'safe':
    case 'seguro':
      return 'safe';
    default:
      return 'suspicious';
  }
}

function getRiskData(riskLevel) {
  const data = {
    phishing: {
      text: 'PELIGROSO',
      emoji: EMOJIS.phishing,
      color: COLORS.phishing,
      icon: ICONS.phishing
    },
    suspicious: {
      text: 'SOSPECHOSO',
      emoji: EMOJIS.suspicious,
      color: COLORS.suspicious,
      icon: ICONS.suspicious
    },
    safe: {
      text: 'SEGURO',
      emoji: EMOJIS.safe,
      color: COLORS.safe,
      icon: ICONS.safe
    }
  };
  
  return data[riskLevel] || data.suspicious;
}

function getRiskDescription(score) {
  if (score <= 30) return 'Riesgo bajo - Mensaje confiable';
  if (score <= 60) return 'Riesgo medio - Verificar remitente';
  return 'Riesgo alto - ¡Precaución!';
}

function formatAnalysisText(analysis) {
  // Formatear el texto humanizado para mejor legibilidad
  return analysis
    .substring(0, 800)  // Aumentado de 500 a 800 caracteres
    .replace(/(\d+\.)/g, '\n$1')
    .replace(/(-)/g, '\n  •')
    .replace(/\*\*(.*?)\*\*/g, '<b>$1</b>')  // Convertir **texto** a <b>texto</b>
    .trim();
}

function getErrorMessage(error) {
  const errorStr = error.toString();
  
  if (errorStr.includes('timeout')) {
    return 'El análisis tardó demasiado. La IA está procesando, intenta nuevamente.';
  } else if (errorStr.includes('401')) {
    return 'Token de autenticación inválido. Verifica la configuración.';
  } else if (errorStr.includes('500')) {
    return 'Error interno del servidor. Intenta en unos minutos.';
  } else {
    return `Error: ${errorStr.substring(0, 100)}`;
  }
}

/**
 * Crear tarjeta de configuración
 */
function createSetupCard() {
  const cardBuilder = CardService.newCardBuilder();
  
  const header = CardService.newCardHeader()
    .setTitle('⚙️ Configuración Requerida')
    .setSubtitle('Detector de Phishing')
    .setImageUrl(ICONS.setup);
  
  cardBuilder.setHeader(header);
  
  const section = CardService.newCardSection();
  const setupText = CardService.newTextParagraph()
    .setText('<b>🔧 Configuración inicial:</b><br><br>1. Ve a <b>Extensiones → Apps Script</b><br>2. Abre <b>Configuración → Propiedades del Script</b><br>3. Agrega: <b>API_TOKEN</b> = <code>test-token-123</code><br>4. Guarda y recarga Gmail<br><br><i>💡 El token te da acceso al análisis con IA avanzada</i>');
  
  section.addWidget(setupText);
  cardBuilder.addSection(section);
  
  return [cardBuilder.build()];
}

/**
 * Crear tarjeta de error
 */
function createErrorCard(title, message) {
  const cardBuilder = CardService.newCardBuilder();
  
  const header = CardService.newCardHeader()
    .setTitle(`❌ ${title}`)
    .setSubtitle('Detector de Phishing')
    .setImageUrl('https://cdn-icons-png.flaticon.com/512/1828/1828843.png');
  
  cardBuilder.setHeader(header);
  
  const section = CardService.newCardSection();
  const errorText = CardService.newTextParagraph()
    .setText(`<b>⚠️ ${message}</b><br><br>💡 <i>Si el problema persiste:</i><br>• Verifica tu conexión<br>• Revisa la configuración del token<br>• Intenta nuevamente en unos segundos`);
  
  section.addWidget(errorText);
  cardBuilder.addSection(section);
  
  return cardBuilder.build();
}