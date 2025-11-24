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
        

        // Crear las 3 tarjetas solo si la respuesta es válida
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
        decodeResultContainer.innerHTML = `<div class="error-box">❌ Token inválido: ${error.message}</div>`;
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
        renderSyntacticPanel(data.syntactic);
        renderSemanticPanel(data.semantic); 
    
        addToHistory('analysis', data);
      } catch (error) {
        setAll(`❌ Error: ${error.message}`);
      }
    }
    
    function renderLexicalTable(lexical) {
      const container = document.getElementById('lexicalResult');
    
      if (!lexical || !Array.isArray(lexical.table) || lexical.table.length === 0) {
        container.textContent = 'No lexical data';
        return;
      }
    
      const rowsHtml = lexical.table.map(row => `
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
      const container = document.getElementById('syntacticResult');
    
      if (!syntactic) {
        container.textContent = 'No syntactic data';
        return;
      }
    
      const segments = syntactic.segments || {};
      const headerJson = segments.header
        ? escapeHtml(JSON.stringify(segments.header, null, 2))
        : '—';
      const payloadJson = segments.payload
        ? escapeHtml(JSON.stringify(segments.payload, null, 2))
        : '—';
    
      const sigRaw = segments.signatureRaw || segments.signatureB64 || '—';
    
      // Si el backend mandó "derivation", la usamos, si no la armamos rápido
      let derivLines = syntactic.derivation && syntactic.derivation.length
        ? syntactic.derivation
        : [
            'S',
            'J',
            'H "." P "." Sg',
            'Base64url(JSON) "." Base64url(JSON) "." Base64url(firma)',
            `${segments.headerB64 || '???'} "." ${segments.payloadB64 || '???'} "." ${segments.signatureB64 || '???'}`
          ];
    
      const derivHtml = derivLines
        .map((line, i) => (i === 0 ? escapeHtml(line) : '⇒ ' + escapeHtml(line)))
        .join('<br>');
    
      const errorsHtml = (syntactic.errors && syntactic.errors.length)
        ? `<ul class="syntactic-errors">
            ${syntactic.errors.map(e => `<li>${escapeHtml(e)}</li>`).join('')}
           </ul>`
        : '<p class="syntactic-ok">Sin errores sintácticos.</p>';
    
      container.innerHTML = `
        <div class="syntactic-wrapper">
          <div class="syntactic-summary">
            <span class="syntactic-status syntactic-status-${syntactic.isValid ? 'ok' : 'error'}">
              ${syntactic.isValid ? 'Válido' : 'Inválido'}
            </span>
          </div>
    
          ${errorsHtml}
    
          <div class="syntactic-grid">
            <!-- IZQUIERDA: Árbol / derivación -->
            <div class="syntactic-left">
              <h4 class="syntactic-title">Árbol de derivación</h4>
              <div class="syntactic-tree">
                ${derivHtml}
              </div>
            </div>
    
            <!-- DERECHA: Contenido header / payload / firma -->
            <div class="syntactic-right">
              <h4 class="syntactic-title">Contenido del token</h4>
    
              <div class="syntactic-block">
                <div class="syntactic-label">Header (JSON)</div>
                <pre class="syntactic-pre">${headerJson}</pre>
              </div>
    
              <div class="syntactic-block">
                <div class="syntactic-label">Payload (JSON)</div>
                <pre class="syntactic-pre">${payloadJson}</pre>
              </div>
    
              <div class="syntactic-block">
                <div class="syntactic-label">Firma (Base64URL)</div>
                <code class="syntactic-code">${escapeHtml(sigRaw)}</code>
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
    
    
    // Llama automáticamente al cargar la página
    window.addEventListener('DOMContentLoaded', loadHistoryFromServer);