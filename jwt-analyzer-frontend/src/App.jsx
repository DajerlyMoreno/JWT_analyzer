import React, { useState, useEffect } from 'react';
import { Unlock, Lock, Microscope, Clock, Zap, ShieldCheck, Copy, Scan, FileCode, Database, Shield, Trash2, Inbox, Key, Terminal, List, Braces, Brain, CheckCircle, XCircle, AlertCircle, AlertTriangle } from 'lucide-react';

const API_URL = "";

export default function JWTAnalyzer() {
  const [activeTab, setActiveTab] = useState('decoder');
  const [history, setHistory] = useState([]);
  const [currentToken, setCurrentToken] = useState('');
  
  const [tokenInput, setTokenInput] = useState('');
  const [decodeResult, setDecodeResult] = useState(null);
  const [showAnalysisBtn, setShowAnalysisBtn] = useState(false);
  
  const [headerInput, setHeaderInput] = useState('{\n    "alg": "HS256", \n    "typ": "JWT"\n}');
  const [payloadInput, setPayloadInput] = useState('{\n    "sub": "1007142936",\n    "name": "Jazmin",\n    "admin": false,\n    "iat": 1516239022,\n    "exp": 250000\n}');
  const [secretInput, setSecretInput] = useState('');
  const [algorithmInput, setAlgorithmInput] = useState('HS256');
  const [encodeResult, setEncodeResult] = useState('Waiting for generation...');
  const [generatedToken, setGeneratedToken] = useState('');
  
  const [analysisTokenInput, setAnalysisTokenInput] = useState('');
  const [analysisSecretInput, setAnalysisSecretInput] = useState('');
  const [lexicalResult, setLexicalResult] = useState('Waiting for analysis...');
  const [syntacticResult, setSyntacticResult] = useState('Waiting for analysis...');
  const [semanticResult, setSemanticResult] = useState('Waiting for analysis...');

  useEffect(() => {
    loadHistoryFromServer();
  }, []);

  const loadHistoryFromServer = async () => {
    try {
      const res = await fetch('/api/history');
      const data = await res.json();
      
      const formattedHistory = data.map(item => ({
        type: item.type,
        data: {
          token: item.token || item.responseData?.token,
          header: item.header || item.responseData?.header,
          payload: item.payload || item.responseData?.payload,
          secret: item.secret,
          algorithm: item.algorithm || item.responseData?.algorithm
        },
        timestamp: new Date(item.createdAt).toLocaleString('es-CO')
      }));
      
      setHistory(formattedHistory);
    } catch (err) {
      console.error('Error loading history:', err);
    }
  };

  const addToHistory = (type, data) => {
    if (type !== 'encode' && type !== 'decode') return;
    
    const now = new Date();
    const newItem = {
      type,
      data,
      timestamp: now.toLocaleString('es-CO', { 
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      })
    };
    
    setHistory(prev => [newItem, ...prev]);
  };

  const decodeToken = async () => {
    const token = tokenInput.trim();
    
    if (!token) {
      setDecodeResult({ error: '⚠️ Please enter a JWT token' });
      setShowAnalysisBtn(false);
      return;
    }

    setDecodeResult({ loading: true });
    setShowAnalysisBtn(false);

    try {
      setCurrentToken(token);
      
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });
      
      const data = await response.json();
      
      if (!data.header || !data.payload || !data.parts) {
        throw new Error('Token inválido');
      }

      setDecodeResult(data);
      addToHistory('decode', data);
      setShowAnalysisBtn(true);
    } catch (error) {
      setDecodeResult({ error: `❌ Token inválido: ${error.message}` });
      setShowAnalysisBtn(false);
    }
  };

  const encodeToken = async () => {
    const header = headerInput.trim();
    const payload = payloadInput.trim();
    const secret = secretInput.trim();
    const algorithm = algorithmInput;
    
    if (!header || !payload || !secret) {
      setEncodeResult('⚠️ Please fill all fields (header, payload, secret)');
      return;
    }
    
    if (secret.length < 32) {
      alert('⚠️ La clave secreta debe tener al menos 256 bits (32 caracteres).');
      setEncodeResult('❌ Token no generado: clave secreta demasiado corta.');
      return;
    }
    
    let parsedHeader, parsedPayload;
    try {
      parsedHeader = JSON.parse(header);
      parsedPayload = JSON.parse(payload);
    } catch (err) {
      setEncodeResult('❌ Error: Header o Payload no son JSON válidos.');
      return;
    }
    
    setEncodeResult('⏳ Generating token...');
    
    try {
      const response = await fetch('/api/encode', {
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
      
      setEncodeResult(data.token);
      setGeneratedToken(data.token);
      addToHistory('encode', { algorithm, token: data.token });
    } catch (error) {
      setEncodeResult(`❌ Error: ${error.message}`);
    }
  };

  const performAnalysis = async () => {
    const token = analysisTokenInput.trim();
    const secret = analysisSecretInput.trim();
    
    if (!token) {
      alert('⚠️ Please enter a JWT token to analyze');
      return;
    }
    
    setLexicalResult('⏳ Analyzing...');
    setSyntacticResult('⏳ Analyzing...');
    setSemanticResult('⏳ Analyzing...');
    
    try {
      const res = await fetch('/api/comprehensive-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, secret })
      });
      
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || `HTTP ${res.status}`);
      }
      
      const data = await res.json();
      
      setLexicalResult(data.lexical);
      setSyntacticResult(data.syntactic);
      setSemanticResult(data.semantic);
    } catch (error) {
      const errMsg = `❌ Error: ${error.message}`;
      setLexicalResult(errMsg);
      setSyntacticResult(errMsg);
      setSemanticResult(errMsg);
    }
  };

  const goToAnalysis = () => {
    setActiveTab('analysis');
    setAnalysisTokenInput(currentToken);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const copyToken = () => {
    if (!generatedToken) return alert('No token to copy');
    navigator.clipboard.writeText(generatedToken);
  };

  const getHistoryField = (item, field) => {
    if (!item || !item.data) return '';
    const data = item.data;
    
    if (field === 'token') {
      return data.token || '';
    }
    
    if (field === 'header') {
      const headerObj = data.header;
      if (!headerObj) return '';
      try {
        return typeof headerObj === 'string' ? headerObj : JSON.stringify(headerObj, null, 2);
      } catch {
        return String(headerObj);
      }
    }
    
    if (field === 'payload') {
      const payloadObj = data.payload;
      if (!payloadObj) return '';
      try {
        return typeof payloadObj === 'string' ? payloadObj : JSON.stringify(payloadObj, null, 2);
      } catch {
        return String(payloadObj);
      }
    }
    
    return '';
  };

  const copyHistoryPart = (index, field) => {
    const item = history[index];
    const text = getHistoryField(item, field);
    
    if (!text) {
      alert('⚠️ No hay datos para copiar en ' + field);
      return;
    }
    
    navigator.clipboard.writeText(text);
  };
  const renderLexical = () => {
    if (typeof lexicalResult === 'string') {
      return <div className="text-center py-8 text-gray-400">{lexicalResult}</div>;
    }
    
    if (!lexicalResult || !Array.isArray(lexicalResult.table) || lexicalResult.table.length === 0) {
      return <div className="text-center py-8 text-gray-400">No lexical data</div>;
    }
    
    return (
      <table className="w-full border-separate border-spacing-0">
        <thead>
          <tr>
            <th className="text-left p-4 bg-gradient-to-r from-green-500/8 to-blue-500/8 text-[#00ff88] uppercase text-xs font-bold tracking-wider border-b-2 border-green-500/30 rounded-tl-xl">#</th>
            <th className="text-left p-4 bg-gradient-to-r from-green-500/8 to-blue-500/8 text-[#00ff88] uppercase text-xs font-bold tracking-wider border-b-2 border-green-500/30">Lexema</th>
            <th className="text-left p-4 bg-gradient-to-r from-green-500/8 to-blue-500/8 text-[#00ff88] uppercase text-xs font-bold tracking-wider border-b-2 border-green-500/30">Token</th>
            <th className="text-left p-4 bg-gradient-to-r from-green-500/8 to-blue-500/8 text-[#00ff88] uppercase text-xs font-bold tracking-wider border-b-2 border-green-500/30 rounded-tr-xl">Estado</th>
          </tr>
        </thead>
        <tbody>
          {lexicalResult.table.map((row, idx) => (
            <tr key={idx} className="hover:bg-gradient-to-r hover:from-green-500/8 hover:to-blue-500/8 transition-all hover:translate-x-1">
              <td className="p-3 border-b border-green-500/10 text-[#00d4ff] font-bold text-center bg-blue-500/5">{row.index}</td>
              <td className="p-3 border-b border-green-500/10">
                <code className="block bg-blue-500/8 p-2 rounded-lg border-l-4 border-[#00d4ff] text-xs text-[#00d4ff] break-all">{row.lexeme}</code>
              </td>
              <td className="p-3 border-b border-green-500/10">
                <span className={`inline-flex items-center justify-center px-3 py-1.5 rounded-full text-xs font-bold uppercase ${
                  row.token === 'SEGMENT' ? 'bg-green-500/25 border border-green-500 text-green-400' :
                  row.token === 'DOT' ? 'bg-blue-500/25 border border-blue-500 text-blue-400' :
                  'bg-pink-500/25 border border-pink-500 text-pink-400'
                }`}>
                  {row.token}
                </span>
              </td>
              <td className="p-3 border-b border-green-500/10 text-gray-400 italic text-xs">{row.estado}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  };

  const renderSemantic = () => {
    if (typeof semanticResult === 'string') {
      return <div className="text-center py-8 text-gray-400">{semanticResult}</div>;
    }
    
    if (!semanticResult) {
      return <div className="text-center py-8 text-gray-400">No semantic data available</div>;
    }

    if (semanticResult.skipped) {
      return (
        <div>
          <div className="flex justify-between items-center p-6 bg-gradient-to-r from-green-500/8 to-blue-500/8 border-b-2 border-green-500/30">
            <div className="flex items-center gap-3 text-lg font-bold uppercase tracking-wider text-red-500">
              <XCircle className="w-6 h-6" />
              <span>Semantic Analysis Skipped</span>
            </div>
          </div>
          <div className="p-8">
            <div className="text-center py-8">
              <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
              <p className="text-base font-semibold text-red-500">
                The semantic analysis was not performed because the syntactic analysis failed.
              </p>
            </div>
          </div>
        </div>
      );
    }

    const isValid = semanticResult.valid === true;
    const hasErrors = semanticResult.errors && semanticResult.errors.length > 0;
    const hasWarnings = semanticResult.warnings && semanticResult.warnings.length > 0;
    const signatureVerified = semanticResult.signatureVerified;
    const algorithm = semanticResult.algorithm || 'Unknown';

    return (
      <div>
        <div className="flex justify-between items-center p-6 bg-gradient-to-r from-green-500/8 to-blue-500/8 border-b-2 border-green-500/30">
          <div className={`flex items-center gap-3 text-lg font-bold uppercase tracking-wider ${isValid ? 'text-[#00ff88]' : 'text-red-500'}`}>
            {isValid ? <CheckCircle className="w-6 h-6" /> : <XCircle className="w-6 h-6" />}
            <span>{isValid ? 'Valid' : 'Invalid'}</span>
          </div>
          <div className="flex gap-3 items-center flex-wrap">
            <span className="inline-flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-blue-500/15 to-green-500/15 border border-blue-500/40 rounded-full text-[#00d4ff] font-mono text-sm font-bold">
              <Key className="w-4 h-4" />
              {algorithm}
            </span>
            {signatureVerified !== null && (
              <span className={`inline-flex items-center gap-2 px-4 py-2 rounded-full text-xs font-semibold uppercase tracking-wider ${
                signatureVerified 
                  ? 'bg-gradient-to-r from-green-500/25 to-green-500/15 text-green-400 border border-green-500' 
                  : 'bg-gradient-to-r from-yellow-500/25 to-yellow-500/15 text-yellow-400 border border-yellow-500'
              }`}>
                {signatureVerified ? <CheckCircle className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
                {signatureVerified ? 'Signature Verified' : 'Signature Invalid'}
              </span>
            )}
          </div>
        </div>

        <div className="p-8">
          {semanticResult.symbolTable?.header && Object.keys(semanticResult.symbolTable.header).length > 0 && (
            <div className="mb-8">
              <div className="flex items-center gap-3 text-base font-bold text-[#00ff88] uppercase tracking-wider mb-4 pb-3 border-b border-green-500/20">
                <FileCode className="w-5 h-5" />
                Header Symbol Table
              </div>
              <table className="w-full border-separate border-spacing-0">
                <thead>
                  <tr>
                    <th className="text-left p-4 bg-gradient-to-r from-green-500/8 to-blue-500/8 text-[#00ff88] uppercase text-xs font-bold tracking-wider border-b-2 border-green-500/30 rounded-tl-xl">Field</th>
                    <th className="text-left p-4 bg-gradient-to-r from-green-500/8 to-blue-500/8 text-[#00ff88] uppercase text-xs font-bold tracking-wider border-b-2 border-green-500/30 rounded-tr-xl">Type</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(semanticResult.symbolTable.header).map(([field, type], idx) => (
                    <tr key={idx} className="hover:bg-gradient-to-r hover:from-green-500/8 hover:to-blue-500/8 transition-all hover:translate-x-1">
                      <td className="p-3 border-b border-green-500/10">
                        <code className="block bg-blue-500/8 p-2 rounded-lg border-l-4 border-[#00d4ff] text-xs text-[#00d4ff] font-semibold">{field}</code>
                      </td>
                      <td className="p-3 border-b border-green-500/10">
                        <span className={`inline-flex items-center justify-center px-3 py-1.5 rounded-full text-xs font-bold uppercase ${
                          type === 'string' ? 'bg-pink-500/25 border border-pink-500 text-pink-400' :
                          type === 'number' ? 'bg-blue-500/25 border border-blue-500 text-blue-400' :
                          type === 'boolean' ? 'bg-green-500/25 border border-green-500 text-green-400' :
                          'bg-purple-500/25 border border-purple-500 text-purple-400'
                        }`}>
                          {type}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {semanticResult.symbolTable?.payload && Object.keys(semanticResult.symbolTable.payload).length > 0 && (
            <div className="mb-8">
              <div className="flex items-center gap-3 text-base font-bold text-[#00ff88] uppercase tracking-wider mb-4 pb-3 border-b border-green-500/20">
                <Database className="w-5 h-5" />
                Payload Symbol Table
              </div>
              <table className="w-full border-separate border-spacing-0">
                <thead>
                  <tr>
                    <th className="text-left p-4 bg-gradient-to-r from-green-500/8 to-blue-500/8 text-[#00ff88] uppercase text-xs font-bold tracking-wider border-b-2 border-green-500/30 rounded-tl-xl">Field</th>
                    <th className="text-left p-4 bg-gradient-to-r from-green-500/8 to-blue-500/8 text-[#00ff88] uppercase text-xs font-bold tracking-wider border-b-2 border-green-500/30 rounded-tr-xl">Type</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(semanticResult.symbolTable.payload).map(([field, type], idx) => (
                    <tr key={idx} className="hover:bg-gradient-to-r hover:from-green-500/8 hover:to-blue-500/8 transition-all hover:translate-x-1">
                      <td className="p-3 border-b border-green-500/10">
                        <code className="block bg-blue-500/8 p-2 rounded-lg border-l-4 border-[#00d4ff] text-xs text-[#00d4ff] font-semibold">{field}</code>
                      </td>
                      <td className="p-3 border-b border-green-500/10">
                        <span className={`inline-flex items-center justify-center px-3 py-1.5 rounded-full text-xs font-bold uppercase ${
                          type === 'string' ? 'bg-pink-500/25 border border-pink-500 text-pink-400' :
                          type === 'number' ? 'bg-blue-500/25 border border-blue-500 text-blue-400' :
                          type === 'boolean' ? 'bg-green-500/25 border border-green-500 text-green-400' :
                          'bg-purple-500/25 border border-purple-500 text-purple-400'
                        }`}>
                          {type}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {hasErrors && (
            <div className="mb-8">
              <div className="flex items-center gap-3 text-base font-bold text-[#00ff88] uppercase tracking-wider mb-4 pb-3 border-b border-green-500/20">
                <AlertCircle className="w-5 h-5" />
                Errors
              </div>
              <div className="flex flex-col gap-3">
                {semanticResult.errors.map((err, idx) => (
                  <div key={idx} className="flex items-start gap-3 p-4 bg-gradient-to-r from-red-500/15 to-red-500/10 border border-red-500/40 rounded-lg text-red-300">
                    <XCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                    <span>{err}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {hasWarnings && (
            <div className="mb-8">
              <div className="flex items-center gap-3 text-base font-bold text-[#00ff88] uppercase tracking-wider mb-4 pb-3 border-b border-green-500/20">
                <AlertTriangle className="w-5 h-5" />
                Warnings
              </div>
              <div className="flex flex-col gap-3">
                {semanticResult.warnings.map((warn, idx) => (
                  <div key={idx} className="flex items-start gap-3 p-4 bg-gradient-to-r from-yellow-500/15 to-yellow-500/10 border border-yellow-500/40 rounded-lg text-yellow-300">
                    <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                    <span>{warn}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {!hasErrors && !hasWarnings && (
            <div className="text-center py-8">
              <CheckCircle className="w-12 h-12 text-[#00ff88] mx-auto mb-4" />
              <p className="text-base font-semibold text-[#00ff88]">No semantic issues detected</p>
            </div>
          )}
        </div>
      </div>
    );
  };
  return (
    <div className="min-h-screen bg-[#0a0e27] text-white font-sans overflow-x-hidden">
      {/* Animated Background */}
      <div className="fixed inset-0 z-0">
        <div className="absolute w-[500px] h-[500px] bg-[radial-gradient(circle,_rgba(0,255,136,0.15)_0%,_transparent_70%)] -top-[250px] -left-[250px] animate-float" />
        <div className="absolute w-[400px] h-[400px] bg-[radial-gradient(circle,_rgba(0,212,255,0.12)_0%,_transparent_70%)] -bottom-[200px] -right-[200px] animate-float-reverse" />
      </div>
      
      {/* Grid Pattern */}
      <div className="fixed inset-0 z-[1] pointer-events-none" style={{
        backgroundImage: 'linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px)',
        backgroundSize: '50px 50px'
      }} />

      {/* Main Container */}
      <div className="relative z-10">
        {/* Header */}
        <header className="py-8 px-4 text-center">
          <h1 className="text-5xl md:text-6xl font-bold bg-gradient-to-r from-[#00ff88] to-[#00d4ff] bg-clip-text text-transparent mb-2 tracking-tight animate-glow">
            JWT ANALYZER
          </h1>
          <p className="text-gray-500 text-sm tracking-[0.2em] uppercase">
            Decode • Encode • Analyze • Verify
          </p>
        </header>

        {/* Tabs */}
        <nav className="flex justify-center gap-4 px-4 py-8 flex-wrap">
          {[
            { id: 'decoder', icon: Unlock, label: 'Decoder' },
            { id: 'encoder', icon: Lock, label: 'Encoder' },
            { id: 'analysis', icon: Microscope, label: 'Analysis' },
            { id: 'history', icon: Clock, label: 'History', badge: history.length }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`relative px-8 py-4 bg-[#151b3d] border-2 rounded-xl font-semibold flex items-center gap-2 overflow-hidden transition-all duration-300 ${
                activeTab === tab.id
                  ? 'border-[#00ff88] text-[#00ff88] bg-gradient-to-r from-green-500/15 to-blue-500/15 shadow-[0_0_30px_rgba(0,255,136,0.3)]'
                  : 'border-green-500/20 text-gray-400 hover:border-[#00ff88] hover:-translate-y-1 hover:shadow-[0_10px_30px_rgba(0,255,136,0.2)]'
              }`}
            >
              <tab.icon className="w-5 h-5" />
              <span>{tab.label}</span>
              {tab.badge !== undefined && (
                <span className="bg-[#00ff88] text-[#0a0e27] px-2 py-0.5 rounded-full text-xs font-bold">
                  {tab.badge}
                </span>
              )}
            </button>
          ))}
        </nav>

        {/* Content */}
        <div className="px-4 pb-16">
          {/* Decoder Tab */}
          {activeTab === 'decoder' && (
            <div className="max-w-4xl mx-auto bg-[#151b3d] border border-green-500/15 rounded-3xl p-10 shadow-[0_20px_60px_rgba(0,0,0,0.5)] relative">
              <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-[#00ff88] to-transparent" />
              
              <h2 className="flex items-center gap-3 text-3xl font-bold mb-4">
                <Unlock className="w-8 h-8" />
                Token Decoder
              </h2>
              <p className="text-gray-500 mb-8 text-sm">
                Paste your JWT token below to decode and analyze its contents
              </p>

              <div className="mb-6">
                <label className="block mb-2 text-gray-400 text-xs font-semibold uppercase tracking-wider">
                  JWT Token
                </label>
                <textarea
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                  className="w-full p-4 bg-[#1f2747] border-2 border-green-500/20 rounded-xl text-white resize-vertical min-h-[120px] focus:outline-none focus:border-[#00ff88] focus:bg-green-500/5 transition-all"
                  placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                />
              </div>

              <button
                onClick={decodeToken}
                className="w-full py-5 bg-gradient-to-r from-[#00ff88] to-[#00cc70] rounded-xl text-[#0a0e27] font-bold text-base uppercase tracking-wider flex items-center justify-center gap-2 transition-all hover:-translate-y-1 hover:shadow-[0_10px_40px_rgba(0,255,136,0.4)]"
              >
                <Zap className="w-5 h-5" />
                Decode Token
              </button>

              <div className="flex items-center gap-2 mt-8 mb-3 text-gray-400 text-xs font-semibold uppercase">
                <Terminal className="w-4 h-4" />
                Decoded Results
              </div>

              {decodeResult?.loading && (
                <div className="text-center py-8 text-gray-400">⏳ Decoding token...</div>
              )}

              {decodeResult?.error && (
                <div className="bg-red-500/10 border border-red-500/40 rounded-xl p-4 text-red-300">
                  {decodeResult.error}
                </div>
              )}

              {decodeResult?.header && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                  <div className="bg-gradient-to-br from-[#0a0e27]/90 to-[#151b3d]/90 border-2 border-green-500/20 rounded-2xl overflow-hidden hover:border-[#00ff88] hover:-translate-y-2 hover:shadow-[0_10px_30px_rgba(0,255,136,0.2)] transition-all">
                    <div className="flex items-center gap-3 px-5 py-4 bg-gradient-to-r from-green-500/10 to-blue-500/10 border-b border-green-500/20 text-[#00ff88] font-bold text-sm uppercase tracking-wider">
                      <FileCode className="w-5 h-5" />
                      Header
                    </div>
                    <pre className="p-5 font-mono text-xs text-[#00d4ff] bg-[#1f2747]/40 min-h-[150px] max-h-[300px] overflow-auto">
                      {JSON.stringify(decodeResult.header, null, 2)}
                    </pre>
                  </div>

                  <div className="bg-gradient-to-br from-[#0a0e27]/90 to-[#151b3d]/90 border-2 border-green-500/20 rounded-2xl overflow-hidden hover:border-[#00ff88] hover:-translate-y-2 hover:shadow-[0_10px_30px_rgba(0,255,136,0.2)] transition-all">
                    <div className="flex items-center gap-3 px-5 py-4 bg-gradient-to-r from-green-500/10 to-blue-500/10 border-b border-green-500/20 text-[#00ff88] font-bold text-sm uppercase tracking-wider">
                      <Database className="w-5 h-5" />
                      Payload
                    </div>
                    <pre className="p-5 font-mono text-xs text-[#00d4ff] bg-[#1f2747]/40 min-h-[150px] max-h-[300px] overflow-auto">
                      {JSON.stringify(decodeResult.payload, null, 2)}
                    </pre>
                  </div>

                  <div className="bg-gradient-to-br from-[#0a0e27]/90 to-[#151b3d]/90 border-2 border-green-500/20 rounded-2xl overflow-hidden hover:border-[#00ff88] hover:-translate-y-2 hover:shadow-[0_10px_30px_rgba(0,255,136,0.2)] transition-all">
                    <div className="flex items-center gap-3 px-5 py-4 bg-gradient-to-r from-green-500/10 to-blue-500/10 border-b border-green-500/20 text-[#00ff88] font-bold text-sm uppercase tracking-wider">
                      <Shield className="w-5 h-5" />
                      Signature
                    </div>
                    <pre className="p-5 font-mono text-xs text-[#00d4ff] bg-[#1f2747]/40 min-h-[150px] max-h-[300px] overflow-auto break-all">
                      {decodeResult.parts?.signatureB64 || 'Signature not available'}
                    </pre>
                  </div>
                </div>
              )}

              {showAnalysisBtn && (
                <button
                  onClick={goToAnalysis}
                  className="w-full mt-4 py-4 bg-gradient-to-r from-[#00d4ff] to-[#0099cc] rounded-xl text-[#0a0e27] font-bold text-sm uppercase tracking-wider flex items-center justify-center gap-2 transition-all hover:-translate-y-1 hover:shadow-[0_10px_40px_rgba(0,212,255,0.4)]"
                >
                  <Microscope className="w-5 h-5" />
                  View Complete Analysis
                </button>
              )}
            </div>
          )}

          {/* Encoder Tab */}
          {activeTab === 'encoder' && (
            <div className="max-w-4xl mx-auto bg-[#151b3d] border border-green-500/15 rounded-3xl p-10 shadow-[0_20px_60px_rgba(0,0,0,0.5)] relative">
              <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-[#00ff88] to-transparent" />
              
              <h2 className="flex items-center gap-3 text-3xl font-bold mb-4">
                <Lock className="w-8 h-8" />
                Token Encoder
              </h2>
              <p className="text-gray-500 mb-8 text-sm">
                Create a new JWT token with custom header, payload and secret
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                <div>
                  <label className="block mb-2 text-gray-400 text-xs font-semibold uppercase tracking-wider">
                    Header
                  </label>
                  <textarea
                    value={headerInput}
                    onChange={(e) => setHeaderInput(e.target.value)}
                    className="w-full p-4 bg-[#1f2747] border-2 border-green-500/20 rounded-xl text-white resize-vertical min-h-[120px] focus:outline-none focus:border-[#00ff88] focus:bg-green-500/5 transition-all font-mono text-sm"
                    placeholder='{"alg": "HS256", "typ": "JWT"}'
                  />
                </div>

                <div>
                  <label className="block mb-2 text-gray-400 text-xs font-semibold uppercase tracking-wider">
                    Payload
                  </label>
                  <textarea
                    value={payloadInput}
                    onChange={(e) => setPayloadInput(e.target.value)}
                    className="w-full p-4 bg-[#1f2747] border-2 border-green-500/20 rounded-xl text-white resize-vertical min-h-[120px] focus:outline-none focus:border-[#00ff88] focus:bg-green-500/5 transition-all font-mono text-sm"
                    placeholder='{"sub": "user123", "name": "John Doe"}'
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                <div>
                  <label className="block mb-2 text-gray-400 text-xs font-semibold uppercase tracking-wider">
                    Secret Key
                  </label>
                  <input
                    type="password"
                    value={secretInput}
                    onChange={(e) => setSecretInput(e.target.value)}
                    className="w-full p-4 bg-[#1f2747] border-2 border-green-500/20 rounded-xl text-white focus:outline-none focus:border-[#00ff88] focus:bg-green-500/5 transition-all"
                    placeholder="your-256-bit-secret"
                  />
                </div>

                <div>
                  <label className="block mb-2 text-gray-400 text-xs font-semibold uppercase tracking-wider">
                    Algorithm
                  </label>
                  <select
                    value={algorithmInput}
                    onChange={(e) => setAlgorithmInput(e.target.value)}
                    className="w-full p-4 bg-[#1f2747] border-2 border-green-500/20 rounded-xl text-white focus:outline-none focus:border-[#00ff88] focus:bg-green-500/5 transition-all"
                  >
                    <option value="HS256">HS256</option>
                    <option value="HS384">HS384</option>
                    <option value="HS512">HS512</option>
                  </select>
                </div>
              </div>

              <button
                onClick={encodeToken}
                className="w-full py-5 bg-gradient-to-r from-[#00ff88] to-[#00cc70] rounded-xl text-[#0a0e27] font-bold text-base uppercase tracking-wider flex items-center justify-center gap-2 transition-all hover:-translate-y-1 hover:shadow-[0_10px_40px_rgba(0,255,136,0.4)]"
              >
                <ShieldCheck className="w-5 h-5" />
                Generate Token
              </button>

              <div className="flex items-center gap-2 mt-8 mb-3 text-gray-400 text-xs font-semibold uppercase">
                <Terminal className="w-4 h-4" />
                Generated Token
              </div>

              <pre className="bg-[#0a0e27] border-2 border-blue-500/30 rounded-xl p-6 mt-4 min-h-[150px] max-h-[400px] overflow-auto font-mono text-sm text-[#00d4ff]">
                {encodeResult}
              </pre>

              {generatedToken && (
                <button
                  onClick={copyToken}
                  className="w-full mt-4 py-4 bg-gradient-to-r from-[#00d4ff] to-[#0099cc] rounded-xl text-[#0a0e27] font-bold text-sm uppercase tracking-wider flex items-center justify-center gap-2 transition-all hover:-translate-y-1 hover:shadow-[0_10px_40px_rgba(0,212,255,0.4)]"
                >
                  <Copy className="w-5 h-5" />
                  Copy Token
                </button>
              )}
            </div>
          )}

          {/* Analysis Tab */}
          {activeTab === 'analysis' && (
            <div className="max-w-4xl mx-auto bg-[#151b3d] border border-green-500/15 rounded-3xl p-10 shadow-[0_20px_60px_rgba(0,0,0,0.5)] relative">
              <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-[#00ff88] to-transparent" />
              
              <h2 className="flex items-center gap-3 text-3xl font-bold mb-4">
                <Microscope className="w-8 h-8" />
                Advanced Token Analysis
              </h2>
              <p className="text-gray-500 mb-8 text-sm">
                Perform comprehensive lexical, syntactic, semantic analysis
              </p>

              <div className="mb-6">
                <label className="block mb-2 text-gray-400 text-xs font-semibold uppercase tracking-wider">
                  JWT Token to Analyze
                </label>
                <textarea
                  value={analysisTokenInput}
                  onChange={(e) => setAnalysisTokenInput(e.target.value)}
                  className="w-full p-4 bg-[#1f2747] border-2 border-green-500/20 rounded-xl text-white resize-vertical min-h-[120px] focus:outline-none focus:border-[#00ff88] focus:bg-green-500/5 transition-all"
                  placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                />
              </div>

              <div className="mb-6">
                <label className="block mb-2 text-gray-400 text-xs font-semibold uppercase tracking-wider">
                  Secret Key (Optional - for signature verification)
                </label>
                <input
                  type="password"
                  value={analysisSecretInput}
                  onChange={(e) => setAnalysisSecretInput(e.target.value)}
                  className="w-full p-4 bg-[#1f2747] border-2 border-green-500/20 rounded-xl text-white focus:outline-none focus:border-[#00ff88] focus:bg-green-500/5 transition-all"
                  placeholder="your-secret-key (leave empty to skip verification)"
                />
              </div>

              <button
                onClick={performAnalysis}
                className="w-full py-5 bg-gradient-to-r from-[#00ff88] to-[#00cc70] rounded-xl text-[#0a0e27] font-bold text-base uppercase tracking-wider flex items-center justify-center gap-2 transition-all hover:-translate-y-1 hover:shadow-[0_10px_40px_rgba(0,255,136,0.4)]"
              >
                <Scan className="w-5 h-5" />
                Run Complete Analysis
              </button>

              {/* Lexical Analysis */}
              <div className="mt-8">
                <div className="flex items-center gap-2 mb-3 text-gray-400 text-xs font-semibold uppercase">
                  <List className="w-4 h-4" />
                  Lexical Analysis
                </div>
                <div className="bg-gradient-to-br from-[#0a0e27]/90 to-[#151b3d]/90 border-2 border-green-500/30 rounded-2xl overflow-hidden shadow-[0_10px_40px_rgba(0,0,0,0.5)] relative">
                  <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-transparent via-[#00ff88] via-[#00d4ff] to-transparent animate-shimmer" />
                  {renderLexical()}
                </div>
              </div>

              {/* Syntactic Analysis */}
              <div className="mt-8">
                <div className="flex items-center gap-2 mb-3 text-gray-400 text-xs font-semibold uppercase">
                  <Braces className="w-4 h-4" />
                  Syntactic Analysis
                </div>
                <pre className="bg-[#0a0e27] border-2 border-blue-500/30 rounded-xl p-6 min-h-[150px] max-h-[400px] overflow-auto font-mono text-sm text-[#00d4ff]">
                  {typeof syntacticResult === 'string' ? syntacticResult : JSON.stringify(syntacticResult, null, 2)}
                </pre>
              </div>

              {/* Semantic Analysis */}
              <div className="mt-8">
                <div className="flex items-center gap-2 mb-3 text-gray-400 text-xs font-semibold uppercase">
                  <Brain className="w-4 h-4" />
                  Semantic Analysis
                </div>
                <div className="bg-gradient-to-br from-[#0a0e27]/90 to-[#151b3d]/90 border-2 border-green-500/30 rounded-2xl overflow-hidden shadow-[0_10px_40px_rgba(0,0,0,0.5)] relative">
                  <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-transparent via-[#00ff88] via-[#00d4ff] to-transparent animate-shimmer" />
                  {renderSemantic()}
                </div>
              </div>
            </div>
          )}

          {/* History Tab */}
          {activeTab === 'history' && (
            <div className="max-w-4xl mx-auto bg-[#151b3d] border border-green-500/15 rounded-3xl p-10 shadow-[0_20px_60px_rgba(0,0,0,0.5)] relative">
              <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-[#00ff88] to-transparent" />
              
              <div className="flex justify-between items-center mb-8">
                <div>
                  <h2 className="flex items-center gap-3 text-3xl font-bold mb-2">
                    <Clock className="w-8 h-8" />
                    Operation History
                  </h2>
                  <p className="text-gray-500 text-sm">Track all your JWT operations</p>
                </div>
              </div>

              {history.length === 0 ? (
                <div className="text-center py-16 text-gray-500">
                  <Inbox className="w-20 h-20 mx-auto mb-4 opacity-30" />
                  <p className="text-lg mb-2">No operations yet</p>
                  <p className="text-sm">Start by decoding or encoding a JWT token</p>
                </div>
              ) : (
                <div className="flex flex-col gap-4">
                  {history.map((item, index) => (
                    <div key={index} className="bg-[#1f2747] border border-green-500/15 rounded-xl p-6 hover:border-[#00ff88] hover:translate-x-2 hover:shadow-[0_5px_20px_rgba(0,255,136,0.1)] transition-all">
                      <div className="flex justify-between items-center mb-4">
                        <div className="flex items-center gap-2 font-semibold text-[#00ff88]">
                          {item.type === 'decode' ? <Unlock className="w-5 h-5" /> : <Lock className="w-5 h-5" />}
                          <span>{item.type.toUpperCase()}</span>
                        </div>
                        <span className="text-gray-500 text-xs">{item.timestamp}</span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="bg-[#0a0e27] rounded-lg border border-blue-500/25 p-4">
                          <div className="flex items-center justify-between text-xs uppercase tracking-wider text-gray-400 mb-2">
                            <span>Token</span>
                            <button
                              onClick={() => copyHistoryPart(index, 'token')}
                              className="p-1 hover:bg-blue-500/10 rounded transition-colors"
                            >
                              <Copy className="w-4 h-4" />
                            </button>
                          </div>
                          <pre className="font-mono text-xs max-h-[180px] overflow-auto text-gray-300 whitespace-pre-wrap break-all">
                            {getHistoryField(item, 'token') || '—'}
                          </pre>
                        </div>

                        <div className="bg-[#0a0e27] rounded-lg border border-blue-500/25 p-4">
                          <div className="flex items-center justify-between text-xs uppercase tracking-wider text-gray-400 mb-2">
                            <span>Header</span>
                            <button
                              onClick={() => copyHistoryPart(index, 'header')}
                              className="p-1 hover:bg-blue-500/10 rounded transition-colors"
                            >
                              <Copy className="w-4 h-4" />
                            </button>
                          </div>
                          <pre className="font-mono text-xs max-h-[180px] overflow-auto text-gray-300 whitespace-pre-wrap break-all">
                            {getHistoryField(item, 'header') || '—'}
                          </pre>
                        </div>

                        <div className="bg-[#0a0e27] rounded-lg border border-blue-500/25 p-4">
                          <div className="flex items-center justify-between text-xs uppercase tracking-wider text-gray-400 mb-2">
                            <span>Payload</span>
                            <button
                              onClick={() => copyHistoryPart(index, 'payload')}
                              className="p-1 hover:bg-blue-500/10 rounded transition-colors"
                            >
                              <Copy className="w-4 h-4" />
                            </button>
                          </div>
                          <pre className="font-mono text-xs max-h-[180px] overflow-auto text-gray-300 whitespace-pre-wrap break-all">
                            {getHistoryField(item, 'payload') || '—'}
                          </pre>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}