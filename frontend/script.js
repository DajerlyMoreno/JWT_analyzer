const API_URL = "http://localhost:3000";
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

      list.innerHTML = history.map(item => `
        <div class="history-item">
          <div class="history-item-header">
            <div class="history-type">
              <i data-lucide="${getHistoryIcon(item.type)}" class="w-5 h-5"></i>
              <span>${item.type.toUpperCase()}</span>
            </div>
            <span class="history-time">${item.timestamp}</span>
          </div>
          <div class="history-content">${JSON.stringify(item.data, null, 2)}</div>
        </div>
      `).join('');
      
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

    function clearHistory() {
      if (confirm('⚠️ This will delete all operation history. Continue?')) {
        history = [];
        updateHistory();
        document.getElementById('historyBadge').textContent = '0';
      }
    }

    async function decodeToken() {
      const token = document.getElementById('tokenInput').value.trim();
      const output = document.getElementById('decodeResult');
      const viewAnalysisBtn = document.getElementById('viewAnalysisBtn');
      
      if (!token) {
        output.textContent = '⚠️ Please enter a JWT token';
        viewAnalysisBtn.classList.add('hidden');
        return;
      }

      output.textContent = '⏳ Decoding token...';
      viewAnalysisBtn.classList.add('hidden');

      try {
        // Guardar el token actual
        currentAnalyzedToken = token;

        // Decodificar token
        const response = await fetch(`${API_URL}/api/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token })
        });
        
        const data = await response.json();
        output.textContent = JSON.stringify(data, null, 2);
        addToHistory('decode', data);

        // Realizar análisis completo en segundo plano
        performBackgroundAnalysis(token);

        // Mostrar botón para ver análisis
        viewAnalysisBtn.classList.remove('hidden');
        lucide.createIcons();

      } catch (error) {
        output.textContent = `❌ Error: ${error.message}`;
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
    
      const outputs = ['lexicalResult', 'syntacticResult', 'semanticResult', 'pumpingResult'];
      const setAll = (text) => outputs.forEach(id => document.getElementById(id).textContent = text);
    
      if (!token) {
        alert('⚠️ Please enter a JWT token to analyze');
        return;
      }
    
      // Validación mínima antes de llamar al backend
      if ((token.match(/\./g) || []).length !== 3 - 1) {
        setAll('❌ Error: el token debe tener exactamente 3 partes separadas por "."');
        return;
      }
    
      setAll('⏳ Analyzing...');
    
      try {
        const res = await fetch(`${API_URL}/api/comprehensive-analysis`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token, secret }) // secret puede ir vacío
        });
    
        // Si viene 400, leo el json y lanzo el error del backend
        if (!res.ok) {
          let errText = `HTTP ${res.status}`;
          try {
            const errData = await res.json();
            if (errData && errData.error) errText = errData.error;
          } catch { /* ignore */ }
          throw new Error(errText);
        }
    
        const data = await res.json();
    
        document.getElementById('lexicalResult').textContent = JSON.stringify(data.lexical, null, 2);
        document.getElementById('syntacticResult').textContent = JSON.stringify(data.syntactic, null, 2);
        document.getElementById('semanticResult').textContent = JSON.stringify(data.semantic, null, 2);
        document.getElementById('pumpingResult').textContent = JSON.stringify(data.pumping, null, 2);
    
        addToHistory('analysis', data);
      } catch (error) {
        setAll(`❌ Error: ${error.message}`);
      }
    }
    
      
    async function loadHistoryFromServer() {
      try {
        const res = await fetch(`${API_URL}/api/history`);
        const data = await res.json();
    
        history = data.map(item => ({
          type: item.type,
          data: item.responseData,
          timestamp: new Date(item.createdAt).toLocaleString('es-CO')
        }));
    
        updateHistory();
        document.getElementById('historyBadge').textContent = history.length;
      } catch (err) {
        console.error('Error al cargar historial:', err);
      }
    }
    
    // Llama automáticamente al cargar la página
    window.addEventListener('DOMContentLoaded', loadHistoryFromServer);