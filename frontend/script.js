const API_URL = "https://yvz6zera5f.execute-api.us-east-1.amazonaws.com";
//const API_URL = "http://localhost:3000";
    lucide.createIcons();

    let history = [];
    let currentAnalyzedToken = null;

    function showTab(tabName, event) {
      document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      
      document.getElementById(tabName).classList.add('active');
      
      if (event && event.target) {
        event.target.closest('.tab-btn').classList.add('active');
      } else {
        // Si no hay event, buscar el botón por el nombre de la tab
        const buttons = document.querySelectorAll('.tab-btn');
        buttons.forEach(btn => {
          if (btn.onclick && btn.onclick.toString().includes(tabName)) {
            btn.classList.add('active');
          }
        });
      }
      
      lucide.createIcons();
    }

    function goToAnalysis() {
      // Cambiar a la pestaña de análisis
      showTab('analysis');
      
      // Llenar el input con el token actual
      if (currentAnalyzedToken) {
        document.getElementById('analysisTokenInput').value = currentAnalyzedToken;
        
        // Scroll suave hacia arriba
        window.scrollTo({ top: 0, behavior: 'smooth' });
        
        // Opcional: ejecutar automáticamente el análisis
        setTimeout(() => {
          performAnalysis();
        }, 500);
      }
    }

    function addToHistory(type, data) {
      // ⚠️ Solo queremos guardar ENCODE y DECODE en el historial
      if (type !== 'encode' && type !== 'decode') {
        return;
      }
    
      const now = new Date();
      history.unshift({
        type,
        data,
        timestamp: now.toLocaleString('es-CO', { 
          day: '2-digit',
          month: 'short',
          year: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        })
      });
      
      updateHistory();
      document.getElementById('historyBadge').textContent = history.length;
    }
    

    function updateHistory() {
      const list = document.getElementById('historyList');
      
      if (history.length === 0) {
        list.innerHTML = `
          <div class="empty-state">
            <i data-lucide="inbox" class="empty-state-icon"></i>
            <p style="font-size: 1.1rem; margin-bottom: 0.5rem;">No operations yet</p>
            <p style="font-size: 0.9rem;">Start by decoding or encoding a JWT token</p>
          </div>
        `;
        lucide.createIcons();
        return;
      }
    
      list.innerHTML = history.map((item, index) => {
        const tokenText   = getHistoryField(item, 'token')   || '—';
        const headerText  = getHistoryField(item, 'header')  || '—';
        const payloadText = getHistoryField(item, 'payload') || '—';
    
        return `
          <div class="history-item">
            <div class="history-item-header">
              <div class="history-type">
                <i data-lucide="${getHistoryIcon(item.type)}" class="w-5 h-5"></i>
                <span>${item.type.toUpperCase()}</span>
              </div>
              <span class="history-time">${item.timestamp}</span>
            </div>
    
            <div class="history-grid">
              <!-- TOKEN -->
              <div class="history-mini-card">
                <div class="history-mini-header">
                  <span>Token</span>
                  <button class="mini-copy-btn" onclick="copyHistoryPart(${index}, 'token')">
                    <i data-lucide="copy" class="w-4 h-4"></i>
                  </button>
                </div>
                <pre class="history-mini-body">${escapeHtml(tokenText)}</pre>
              </div>
    
              <!-- HEADER -->
              <div class="history-mini-card">
                <div class="history-mini-header">
                  <span>Header</span>
                  <button class="mini-copy-btn" onclick="copyHistoryPart(${index}, 'header')">
                    <i data-lucide="copy" class="w-4 h-4"></i>
                  </button>
                </div>
                <pre class="history-mini-body">${escapeHtml(headerText)}</pre>
              </div>
    
              <!-- PAYLOAD -->
              <div class="history-mini-card">
                <div class="history-mini-header">
                  <span>Payload</span>
                  <button class="mini-copy-btn" onclick="copyHistoryPart(${index}, 'payload')">
                    <i data-lucide="copy" class="w-4 h-4"></i>
                  </button>
                </div>
                <pre class="history-mini-body">${escapeHtml(payloadText)}</pre>
              </div>
            </div>
          </div>
        `;
      }).join('');
      
      lucide.createIcons();
    }
    

    function getHistoryIcon(type) {
      const icons = {
        'decode': 'unlock',
        'encode': 'lock',
        'analysis': 'microscope'
      };
      return icons[type] || 'file';
    }

    async function clearHistory() {
      if (!confirm('⚠️ This will delete all operation history. Continue?')) {
        return;
      }
    
      try {
        // 👇 BORRAR EN LA BASE
        const res = await fetch(`${API_URL}/api/history`, {
          method: 'DELETE'
        });
    
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          throw new Error(err.error || `HTTP ${res.status}`);
        }
    
        const data = await res.json();
        console.log("Servidor respondió:", data);
    
        // 👇 BORRAR EN MEMORIA / UI
        history = [];
        updateHistory();
        document.getElementById('historyBadge').textContent = '0';
      } catch (err) {
        console.error('Error al borrar historial en el servidor:', err);
        alert('❌ No se pudo borrar el historial en el servidor: ' + err.message);
      }
    }

    async function decodeToken() {
      const token = document.getElementById('tokenInput').value.trim();
      const decodeResultContainer = document.getElementById('decodeResult');
      const viewAnalysisBtn = document.getElementById('viewAnalysisBtn');
      
      if (!token) {
        decodeResultContainer.innerHTML = '<div class="error-box">⚠️ Please enter a JWT token</div>';
        viewAnalysisBtn.classList.add('hidden');
        return;
      }

      decodeResultContainer.innerHTML = '<div class="loading-box">⏳ Decoding token...</div>';
      viewAnalysisBtn.classList.add('hidden');

      try {
        currentAnalyzedToken = token;

        const response = await fetch(`${API_URL}/api/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token })
        });
        
        const data = await response.json();

        // 🔴 Si el backend responde 400, mostramos el mensaje de error
        if (!response.ok) {
          throw new Error(data.error || `HTTP ${response.status}`);
        }

        // ✅ Solo si todo fue bien, construimos las tarjetas
        decodeResultContainer.innerHTML = `
          <div class="decode-card">
            <div class="decode-card-header">
              <i data-lucide="file-code" class="w-5 h-5"></i>
              <span>Header</span>
            </div>
            <pre id="headerResult" class="decode-content">${JSON.stringify(data.header, null, 2)}</pre>
          </div>

          <div class="decode-card">
            <div class="decode-card-header">
              <i data-lucide="database" class="w-5 h-5"></i>
              <span>Payload</span>
            </div>
            <pre id="payloadResult" class="decode-content">${JSON.stringify(data.payload, null, 2)}</pre>
          </div>

          <div class="decode-card">
            <div class="decode-card-header">
              <i data-lucide="shield" class="w-5 h-5"></i>
              <span>Signature</span>
            </div>
            <pre id="signatureResult" class="decode-content">${data.parts.signatureB64 || 'Signature not available'}</pre>
          </div>
        `;

        addToHistory('decode', data);
        performBackgroundAnalysis(token);
        viewAnalysisBtn.classList.remove('hidden');
        lucide.createIcons();

      } catch (error) {
        decodeResultContainer.innerHTML = `<div class="error-box">❌ ${error.message}</div>`;
        viewAnalysisBtn.classList.add('hidden');
      }
    }


    async function performBackgroundAnalysis(token) {
      try {
        const response = await fetch(`${API_URL}/api/comprehensive-analysis`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token })
        });
        
        const data = await response.json();
        
        // Guardar resultados en variables globales para acceso rápido
        window.cachedAnalysis = data;
        
        console.log('✅ Analysis completed in background');
      } catch (error) {
        console.error('Background analysis failed:', error);
      }
    }

    async function verifySignature() {
      const token = document.getElementById('analysisTokenInput').value.trim();
      const secret = document.getElementById('secretInput') ? document.getElementById('secretInput').value.trim() : '';
    
      if (!token || !secret) {
        alert('⚠️ Ingresa token y secret para verificar firma');
        return;
      }
    
      try {
        const res = await fetch(`${API_URL}/api/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token, secret })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Error verificando firma');
    
        // Muestra el resultado dentro del bloque semántico para coherencia
        const current = document.getElementById('semanticResult');
        let obj;
        try { obj = JSON.parse(current.textContent); } catch { obj = {}; }
        obj.signatureVerified = data.signatureVerified;
        obj.algorithm = data.algorithm;
        document.getElementById('semanticResult').textContent = JSON.stringify(obj, null, 2);
    
        addToHistory('analysis', { verifyOnly: true, ...data });
      } catch (e) {
        alert(`❌ ${e.message}`);
      }
    }

    async function verifySignatureFromDecoder() {
      // Usamos el último token decodificado en el Decoder
      const token =
        (currentAnalyzedToken && currentAnalyzedToken.trim()) ||
        document.getElementById("tokenInput").value.trim();

      const secret = document
        .getElementById("decoderSecretInput")
        .value.trim();

      const resultBox = document.getElementById("decoderSignatureResult");

      if (!token) {
        resultBox.textContent = "⚠️ First decode a JWT token in this tab.";
        return;
      }

      if (!secret) {
        resultBox.textContent = "⚠️ Please enter the secret to verify the signature.";
        return;
      }

      resultBox.textContent = "⏳ Verifying signature...";

      try {
        const res = await fetch(`${API_URL}/api/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token, secret }),
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || `HTTP ${res.status}`);
        }

        if (data.signatureVerified) {
          // Firma válida
          resultBox.textContent = `✅ Signature VALID (alg: ${data.algorithm || "unknown"})`;
          resultBox.classList.remove("error-box");
          resultBox.classList.add("success-box");
        } else {
          // Firma inválida
          resultBox.textContent = `❌ Signature INVALID (alg: ${data.algorithm || "unknown"})`;
          resultBox.classList.remove("success-box");
          resultBox.classList.add("error-box");
        }
      } catch (err) {
        resultBox.textContent = `❌ Error verifying signature: ${err.message}`;
        resultBox.classList.remove("success-box");
        resultBox.classList.add("error-box");
      }
    }

    

    async function encodeToken() {
      const header = document.getElementById('headerInput').value.trim();
      const payload = document.getElementById('payloadInput').value.trim();
      const secret = document.getElementById('secretInput').value.trim();
      const algorithm = document.getElementById('algorithmInput').value;
      const output = document.getElementById('encodeResult');
      const copyBtn = document.getElementById("copyTokenBtn");
    
      if (!header || !payload || !secret) {
        output.textContent = '⚠️ Please fill all fields (header, payload, secret)';
        return;
      }
    
      const minLength = 32;
      if (secret.length < minLength) {
        alert("⚠️ La clave secreta debe tener al menos 256 bits (32 caracteres).");
        output.textContent = '❌ Token no generado: clave secreta demasiado corta.';
        return;
      }
    
      let parsedHeader, parsedPayload;
      try {
        parsedHeader = JSON.parse(header);
        parsedPayload = JSON.parse(payload);
      } catch (err) {
        output.textContent = "❌ Error: Header o Payload no son JSON válidos.";
        return;
      }
    
      output.textContent = '⏳ Generating token...';
      copyBtn.classList.add("hidden");
    
      try {
        const response = await fetch(`${API_URL}/api/encode`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            header: parsedHeader,
            payload: parsedPayload,
            secret,
            algorithm
          })
        });
    
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Error generando el token');
    
        // ✅ Mostrar solo el token, nada más
        output.textContent = data.token;
    
        // Guardar token para copiar o analizar
        window.generatedToken = data.token;
        copyBtn.classList.remove("hidden");
    
        // Guardar en historial
        addToHistory('encode', { algorithm, token: data.token });
    
      } catch (error) {
        output.textContent = `❌ Error: ${error.message}`;
      }
    }


    // ##### FUNCIONES PARA EVITAR DISCREPANCIA ENTRE LA SELECCION DEL ALGORITMO
    
    
    // Utilidad para pretty-print JSON con indentación
    function formatJson(obj) {
      return JSON.stringify(obj, null, 4);
    }

    // Cuando cambia el select de algoritmo → actualizar header.alg
    function onAlgorithmChange() {
      const select = document.getElementById("algorithmInput");
      const headerTextarea = document.getElementById("headerInput");
      const alg = select.value;

      let headerObj;

      // Intentamos parsear el header actual; si está roto, creamos uno nuevo
      try {
        headerObj = JSON.parse(headerTextarea.value || "{}");
      } catch (e) {
        headerObj = {};
      }

      // Forzamos el algoritmo seleccionado
      headerObj.alg = alg;

      // Si no hay typ, lo ponemos por defecto
      if (!headerObj.typ) {
        headerObj.typ = "JWT";
      }

      // Reescribimos el textarea formateado
      headerTextarea.value = formatJson(headerObj);
    }

    // Cuando el usuario edita el header → sincronizar el select si el alg es válido
    function onHeaderChanged() {
      const headerTextarea = document.getElementById("headerInput");
      const select = document.getElementById("algorithmInput");

      let headerObj;
      try {
        headerObj = JSON.parse(headerTextarea.value);
      } catch (e) {
        // Mientras el JSON esté mal escrito, no hacemos nada
        return;
      }

      const alg = headerObj.alg;

      // Solo sincronizamos si es uno de los tres soportados
      const allowed = ["HS256", "HS384", "HS512"];
      if (typeof alg === "string" && allowed.includes(alg)) {
        select.value = alg;
      }
    }


    //######

    function copyToken() {
        if (!window.generatedToken) return alert("No token to copy");
        navigator.clipboard.writeText(window.generatedToken);
    }

    async function performAnalysis() {
      const tokenRaw = document.getElementById('analysisTokenInput').value;
      const token = (tokenRaw || "").trim();
      const secretEl = document.getElementById('secretInput');
      const secret = secretEl ? (secretEl.value || "").trim() : "";
    
      const outputs = ['lexicalResult', 'syntacticResult', 'semanticResult'];
      const setAll = (text) => outputs.forEach(id => document.getElementById(id).textContent = text);
    
      if (!token) {
        alert('⚠️ Please enter a JWT token to analyze');
        return;
      }
    
      setAll('⏳ Analyzing...');
    
      try {
        const res = await fetch(`${API_URL}/api/comprehensive-analysis`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token, secret })
        });
    
        if (!res.ok) {
          let errText = `HTTP ${res.status}`;
          try {
            const errData = await res.json();
            if (errData && errData.error) errText = errData.error;
          } catch { /* ignore */ }
          throw new Error(errText);
        }
    
        const data = await res.json();
    
        renderLexicalTable(data.lexical);
        setSyntacticAnalysis(data.syntactic);

        renderSemanticPanel(data.semantic); 
    
        addToHistory('analysis', data);
      } catch (error) {
        setAll(`❌ Error: ${error.message}`);
      }
    }
    
    function renderLexicalTable(lexical) {
      const container = document.getElementById('lexicalResult');

      if (!lexical || !Array.isArray(lexical.table)) {
        container.textContent = 'No lexical data';
        return;
      }

      const table = lexical.table;

      // Token original escrito en el área de análisis
      const tokenRaw = document.getElementById("analysisTokenInput").value.trim();
      const parts = tokenRaw ? tokenRaw.split(".") : [];

      // 🔍 ¿Algún SEGMENT tiene error de Base64URL u otro error?
      const hasSegmentError = table.some(
        (row) =>
          row.token === "SEGMENT" &&
          typeof row.estado === "string" &&
          row.estado.includes("ERROR")
      );

      let structureMessage = "";
      let structureClass = "";

      // ==============================
      //  LÓGICA DEL MENSAJE RESUMEN
      // ==============================
      if (!tokenRaw) {
        structureMessage = "Ingresa un JWT para realizar el análisis léxico.";
        structureClass = "lexical-error-box";
      } else if (parts.length < 3) {
        structureMessage =
          `❌ Estructura inválida: el JWT tiene SOLO ${parts.length} segmentos. ` +
          `Debe tener exactamente 3 (HEADER.PAYLOAD.SIGNATURE).`;
        if (hasSegmentError) {
          structureMessage +=
            " Además, se detectaron segmentos con contenido Base64URL inválido.";
        }
        structureClass = "lexical-error-box";
      } else if (parts.length > 3) {
        structureMessage =
          `❌ Estructura inválida: el JWT tiene ${parts.length} segmentos. ` +
          `Un JWT válido solo debe tener 3 (HEADER.PAYLOAD.SIGNATURE).`;
        if (hasSegmentError) {
          structureMessage +=
            " También se encontraron segmentos con Base64URL inválido.";
        }
        structureClass = "lexical-error-box";
      } else {
        // parts.length === 3
        if (hasSegmentError) {
          structureMessage =
            "❌ Estructura correcta (3 segmentos), PERO al menos uno de los segmentos no es Base64URL válido. El token es léxicamente inválido.";
          structureClass = "lexical-error-box";
        } else {
          structureMessage =
            "✔️ Estructura y contenido válidos: el JWT tiene 3 segmentos y todos los bloques cumplen Base64URL.";
          structureClass = "lexical-ok-box";
        }
      }

      const rowsHtml = table.map(row => `
        <tr>
          <td class="lexical-td index">${row.index}</td>
          <td class="lexical-td lexeme">
            <code>${escapeHtml(row.lexeme)}</code>
          </td>
          <td class="lexical-td token">
            <span class="token-pill token-${row.token.toLowerCase()}">
              ${row.token}
            </span>
          </td>
          <td class="lexical-td estado">${row.estado}</td>
        </tr>
      `).join('');

      container.innerHTML = `
        <div class="${structureClass}" style="margin-bottom: 1rem;">
          ${structureMessage}
        </div>

        <table class="lexical-table">
          <thead>
            <tr>
              <th class="lexical-th">#</th>
              <th class="lexical-th">Lexema</th>
              <th class="lexical-th">Token</th>
              <th class="lexical-th">Estado</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml}
          </tbody>
        </table>
      `;
    }



    function renderSyntacticPanel(syntactic) {
      const container = document.getElementById("syntacticResult");
      if (!container) return;

      if (!syntactic) {
        container.textContent = "No syntactic data";
        return;
      }

      const isValid = syntactic.isValid;
      const errors = syntactic.errors || [];
      const segments = syntactic.segments || {};

      const h = segments.headerB64 || "(no header)";
      const p = segments.payloadB64 || "(no payload)";
      const s = segments.signatureB64 || "(no signature)";

      container.innerHTML = `
        <div class="syntactic-box">

          <div class="synt-header-row">
            <span class="synt-status ${isValid ? "ok" : "error"}">
              ${isValid ? "🟢 Válido" : "🔴 Inválido"}
            </span>
            ${
              errors.length === 0
                ? `<span class="synt-subtext">Sin errores sintácticos.</span>`
                : ""
            }
          </div>

          ${
            errors.length > 0
              ? `
          <div class="synt-section">
            <h4>Errores sintácticos</h4>
            <ul class="synt-error-list">
              ${errors.map(e => `<li>${e}</li>`).join("")}
            </ul>
          </div>`
              : ""
          }

          <div class="synt-section">
            <h4>Árbol de derivación</h4>
            <pre class="code-block tree-block">${
              syntactic.asciiTree || "Árbol no disponible"
            }</pre>
          </div>

          <div class="synt-section">
            <h4>Estructura reconocida</h4>
            <pre class="code-block">
    S  → J
    J  → H "." P "." Sg
    H, P, Sg → SEGMENT (Base64URL)
            </pre>
          </div>

          <div class="synt-section">
            <h4>Segmentos</h4>
            <div class="segment-grid">
              <div class="segment-card">
                <div class="segment-label">HEADER</div>
                <div class="segment-value">${h}</div>
              </div>
              <div class="segment-card">
                <div class="segment-label">PAYLOAD</div>
                <div class="segment-value">${p}</div>
              </div>
              <div class="segment-card">
                <div class="segment-label">SIGNATURE</div>
                <div class="segment-value">${s}</div>
              </div>
            </div>
          </div>

        </div>
      `;
    }

    async function loadHistoryFromServer() {
      try {
        const res = await fetch(`${API_URL}/api/history`);
        const data = await res.json();
    
        history = data.map(item => ({
          type: item.type,
          // 👇 Aquí armamos un objeto "data" uniforme leyendo LOS CAMPOS RAÍZ
          data: {
            token: item.token || item.responseData?.token,
            header: item.header || item.responseData?.header,
            payload: item.payload || item.responseData?.payload,
            secret: item.secret,                        // si lo guardas
            algorithm: item.algorithm || item.responseData?.algorithm
          },
          timestamp: new Date(item.createdAt).toLocaleString('es-CO')
        }));
    
        updateHistory();
        document.getElementById('historyBadge').textContent = history.length;
      } catch (err) {
        console.error('Error al cargar historial:', err);
      }
    }
    
    function getHistoryField(item, field) {
      if (!item || !item.data) return '';
    
      // Normalizar posibles estructuras
      const data = item.data;
    
      if (field === 'token') {
        return (
          data.token ||
          data.jwt ||
          data.inputToken ||
          data.originalToken ||
          data.decodedToken ||
          ''
        );
      }
    
      if (field === 'header') {
        const headerObj =
          data.header ||
          data.decodedHeader ||
          (data.decoded && data.decoded.header) ||
          (data.analysis && data.analysis.header) ||
          null;
    
        if (!headerObj) return '';
        try {
          return typeof headerObj === 'string'
            ? headerObj
            : JSON.stringify(headerObj, null, 2);
        } catch {
          return String(headerObj);
        }
      }
    
      if (field === 'payload') {
        const payloadObj =
          data.payload ||
          data.decodedPayload ||
          (data.decoded && data.decoded.payload) ||
          (data.analysis && data.analysis.payload) ||
          null;
    
        if (!payloadObj) return '';
        try {
          return typeof payloadObj === 'string'
            ? payloadObj
            : JSON.stringify(payloadObj, null, 2);
        } catch {
          return String(payloadObj);
        }
      }
    
      return '';
    }
    
    function copyHistoryPart(index, field) {
      const item = history[index];
      const text = getHistoryField(item, field);
    
      if (!text) {
        alert('⚠️ No hay datos para copiar en ' + field);
        return;
      }
    
      navigator.clipboard.writeText(text)
        .then(() => {
          // Opcional: puedes mostrar un pequeño mensaje o toast
          console.log(`✅ Copiado ${field} desde historial`);
        })
        .catch(() => {
          alert('❌ No se pudo copiar al portapapeles');
        });
    }
    
    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }
    
    function renderSemanticPanel(semantic) {
      const container = document.getElementById('semanticResult');
    
      if (!semantic) {
        container.innerHTML = `
          <div class="semantic-empty">No semantic data available</div>
        `;
        return;
      }
    
      // 🛑 Si el análisis semántico fue saltado
      if (semantic.skipped) {
        container.innerHTML = `
          <div class="semantic-header">
            <div class="semantic-status invalid">
              <i data-lucide="x-circle" class="w-6 h-6"></i>
              <span>Semantic Analysis Skipped</span>
            </div>
          </div>
    
          <div class="semantic-body">
            <div class="semantic-section">
              <div class="semantic-empty">
                <i data-lucide="alert-circle" style="width: 48px; height: 48px; color: var(--neon-red); margin-bottom: 0.5rem;"></i>
                <p style="font-size: 1rem; font-weight: 600; color: var(--neon-red);">
                  p
                </p>
              </div>
            </div>
          </div>
        `;
    
        lucide.createIcons();
        return;
      }
    
      // ======================
      //    CASO NORMAL
      // ======================
      const isValid = semantic.valid === true;
      const hasErrors = semantic.errors && semantic.errors.length > 0;
      const hasWarnings = semantic.warnings && semantic.warnings.length > 0;
      const signatureVerified = semantic.signatureVerified;
      const algorithm = semantic.algorithm || 'Unknown';
    
      // ======================
      //     HEADER
      // ======================
      let headerHtml = `
        <div class="semantic-header">
          <div class="semantic-status ${isValid ? 'valid' : 'invalid'}">
            <i data-lucide="${isValid ? 'check-circle' : 'x-circle'}" class="w-6 h-6"></i>
            <span>${isValid ? 'Valid' : 'Invalid'}</span>
          </div>
    
          <div style="display: flex; gap: 0.75rem; align-items: center;">
            <span class="semantic-algorithm">
              <i data-lucide="key" class="w-4 h-4"></i>
              ${escapeHtml(algorithm)}
            </span>
      `;
    
      if (signatureVerified !== null) {
        headerHtml += `
          <span class="semantic-badge ${signatureVerified ? 'verified' : 'not-verified'}">
            <i data-lucide="${signatureVerified ? 'shield-check' : 'shield-alert'}" class="w-4 h-4"></i>
            ${signatureVerified ? 'Signature Verified' : 'Signature Invalid'}
          </span>
        `;
      }
    
      headerHtml += `
          </div>
        </div>
      `;
    
      // ======================
      //     BODY
      // ======================
      let bodyHtml = `<div class="semantic-body">`;
    
      // -------- Symbol Table: Header --------
      if (semantic.symbolTable?.header) {
        const headerFields = Object.entries(semantic.symbolTable.header);
        if (headerFields.length > 0) {
          bodyHtml += `
            <div class="semantic-section">
              <div class="semantic-section-title">
                <i data-lucide="file-code" class="w-5 h-5"></i>
                Header Symbol Table
              </div>
              <table class="semantic-table">
                <thead>
                  <tr><th>Field</th><th>Type</th></tr>
                </thead>
                <tbody>
                  ${headerFields.map(([field, type]) => `
                    <tr>
                      <td class="semantic-field">${escapeHtml(field)}</td>
                      <td><span class="semantic-type ${type}">${escapeHtml(type)}</span></td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `;
        }
      }
    
      // -------- Symbol Table: Payload --------
      if (semantic.symbolTable?.payload) {
        const payloadFields = Object.entries(semantic.symbolTable.payload);
        if (payloadFields.length > 0) {
          bodyHtml += `
            <div class="semantic-section">
              <div class="semantic-section-title">
                <i data-lucide="database" class="w-5 h-5"></i>
                Payload Symbol Table
              </div>
              <table class="semantic-table">
                <thead>
                  <tr><th>Field</th><th>Type</th></tr>
                </thead>
                <tbody>
                  ${payloadFields.map(([field, type]) => `
                    <tr>
                      <td class="semantic-field">${escapeHtml(field)}</td>
                      <td><span class="semantic-type ${type}">${escapeHtml(type)}</span></td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `;
        }
      }
    
      // -------- Errors --------
      if (hasErrors) {
        bodyHtml += `
          <div class="semantic-section">
            <div class="semantic-section-title">
              <i data-lucide="alert-circle" class="w-5 h-5"></i>
              Errors
            </div>
            <div class="semantic-messages">
              ${semantic.errors.map(err => `
                <div class="semantic-message error">
                  <i data-lucide="x-circle" class="w-5 h-5 semantic-message-icon"></i>
                  <span>${escapeHtml(err)}</span>
                </div>
              `).join('')}
            </div>
          </div>
        `;
      }
    
      // -------- Warnings --------
      if (hasWarnings) {
        bodyHtml += `
          <div class="semantic-section">
            <div class="semantic-section-title">
              <i data-lucide="alert-triangle" class="w-5 h-5"></i>
              Warnings
            </div>
            <div class="semantic-messages">
              ${semantic.warnings.map(warn => `
                <div class="semantic-message warning">
                  <i data-lucide="alert-triangle" class="w-5 h-5 semantic-message-icon"></i>
                  <span>${escapeHtml(warn)}</span>
                </div>
              `).join('')}
            </div>
          </div>
        `;
      }
    
      // -------- No issues --------
      if (!hasErrors && !hasWarnings) {
        bodyHtml += `
          <div class="semantic-section">
            <div class="semantic-empty">
              <i data-lucide="check-circle" style="width: 48px; height: 48px; color: var(--neon-green); margin-bottom: 0.5rem;"></i>
              <p style="font-size: 1rem; font-weight: 600; color: var(--neon-green);">
                No semantic issues detected
              </p>
            </div>
          </div>
        `;
      }
    
      bodyHtml += `</div>`; // close semantic-body
    
      container.innerHTML = headerHtml + bodyHtml;
      lucide.createIcons();
    }
    
    
  function asciiFromJsonTree(node, prefix = "", isLast = true, acc = []) {
    if (!node) return acc;

    const connector = prefix === "" ? "" : (isLast ? "└── " : "├── ");
    acc.push(prefix + connector + (node.label || node.type || "(nodo)"));

    const children = node.children || [];
    const nextPrefix = prefix + (isLast ? "    " : "│   ");

    children.forEach((child, index) => {
      asciiFromJsonTree(
        child,
        nextPrefix,
        index === children.length - 1,
        acc
      );
    });

    return acc;
  }



function setSyntacticAnalysis(syntactic) {
  const container = document.getElementById("syntacticResult");
  if (!container) return;

  if (!syntactic) {
    container.innerHTML = `<div class="syntactic-empty">No syntactic data</div>`;
    return;
  }

  const isValid    = !!syntactic.isValid;
  const errors     = syntactic.errors || [];
  const grammar    = syntactic.grammar || "";
  const derivation = syntactic.derivation || [];
  const segments   = syntactic.segments || {};
  const asciiJwt   = syntactic.asciiTree || "Árbol no disponible";

  const h = segments.headerB64  || "(no header)";
  const p = segments.payloadB64 || "(no payload)";
  const s = segments.signatureB64 || "(no signature)";

  // Árboles JSON desde el parser formal
  let headerJsonAscii = null;
  let payloadJsonAscii = null;

  if (syntactic.jsonTrees?.header) {
    const lines = asciiFromJsonTree({
      label: "HEADER",
      children: [syntactic.jsonTrees.header]
    });
    headerJsonAscii = lines.join("\n");
  }

  if (syntactic.jsonTrees?.payload) {
    const lines = asciiFromJsonTree({
      label: "PAYLOAD",
      children: [syntactic.jsonTrees.payload]
    });
    payloadJsonAscii = lines.join("\n");
  }

  // ----- TABS para seleccionar árbol -----
  let tabsHtml   = "";
  let panelsHtml = "";

  // Siempre mostramos el árbol JWT
  tabsHtml += `
    <button class="tree-tab active" data-target="tree-jwt">JWT</button>
  `;
  panelsHtml += `
    <pre id="tree-jwt" class="tree-panel active"><code>${escapeHtml(asciiJwt)}</code></pre>
  `;

  if (headerJsonAscii) {
    tabsHtml += `
      <button class="tree-tab" data-target="tree-header">HEADER (JSON)</button>
    `;
    panelsHtml += `
      <pre id="tree-header" class="tree-panel"><code>${escapeHtml(headerJsonAscii)}</code></pre>
    `;
  }

  if (payloadJsonAscii) {
    tabsHtml += `
      <button class="tree-tab" data-target="tree-payload">PAYLOAD (JSON)</button>
    `;
    panelsHtml += `
      <pre id="tree-payload" class="tree-panel"><code>${escapeHtml(payloadJsonAscii)}</code></pre>
    `;
  }

  // ----- GRAMÁTICA -----
  const grammarHtml = grammar
    ? `<pre class="code-block">${escapeHtml(grammar)}</pre>`
    : `<pre class="code-block">Gramática no disponible</pre>`;

  // ----- DERIVACIÓN -----
  const derivationHtml =
    derivation && derivation.length
      ? `<pre class="code-block">${escapeHtml(derivation.join("\n⇒ "))}</pre>`
      : `<pre class="code-block">Derivación no disponible</pre>`;

  // ----- ERRORES -----
  const errorsHtml =
    errors.length > 0
      ? `
      <div class="synt-section">
        <h4>Errores sintácticos</h4>
        <ul class="synt-error-list">
          ${errors.map(e => `<li>${escapeHtml(e)}</li>`).join("")}
        </ul>
      </div>
    `
      : "";

  // ----- SEGMENTOS -----
  const segmentsHtml = `
    <div class="synt-section">
      <h4>Segmentos reconocidos</h4>
      <div class="segment-grid">
        <div class="segment-card">
          <div class="segment-label">HEADER</div>
          <div class="segment-value">${escapeHtml(h)}</div>
        </div>
        <div class="segment-card">
          <div class="segment-label">PAYLOAD</div>
          <div class="segment-value">${escapeHtml(p)}</div>
        </div>
        <div class="segment-card">
          <div class="segment-label">SIGNATURE</div>
          <div class="segment-value">${escapeHtml(s)}</div>
        </div>
      </div>
    </div>
  `;

  // ----- ARMAMOS TODO EL PANEL -----
  container.innerHTML = `
    <div class="syntactic-box">
      <div class="synt-header-row">
        <div class="synt-status ${isValid ? "ok" : "error"}">
          <span class="dot"></span>
          <span>${isValid ? "🟢 TOKEN VÁLIDO" : "🔴 TOKEN INVÁLIDO"}</span>
        </div>
        <span class="synt-subtext">
          ${isValid && errors.length === 0
            ? "Sin errores sintácticos en la estructura JWT."
            : errors.length > 0
              ? "Se encontraron errores en la estructura del token."
              : ""}
        </span>
      </div>

      ${errorsHtml}

      <div class="synt-section">
        <h4>Árbol de derivación</h4>
        <div class="tree-tabs">
          ${tabsHtml}
        </div>
        <div class="tree-panels">
          ${panelsHtml}
        </div>
      </div>

      <div class="synt-section">
        <h4>Gramática usada (GLC)</h4>
        ${grammarHtml}
      </div>

      <div class="synt-section">
        <h4>Derivación paso a paso</h4>
        ${derivationHtml}
      </div>

      ${segmentsHtml}
    </div>
  `;

  // ----- LÓGICA DE TABS -----
  const tabs   = container.querySelectorAll(".tree-tab");
  const panels = container.querySelectorAll(".tree-panel");

  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const targetId = tab.dataset.target;

      tabs.forEach(t => t.classList.remove("active"));
      panels.forEach(p => p.classList.remove("active"));

      tab.classList.add("active");
      const panel = container.querySelector("#" + targetId);
      if (panel) panel.classList.add("active");
    });
  });
}


    // Llama automáticamente al cargar la página
    window.addEventListener('DOMContentLoaded', loadHistoryFromServer);