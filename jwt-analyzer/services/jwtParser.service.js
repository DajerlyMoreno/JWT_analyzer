// services/jwtParser.service.js

/**
 * Parser sintáctico descendente para la estructura compacta de un JWT.
 *
 * Gramática (a nivel de tokens):
 *
 *   S  → J
 *   J  → H DOT P DOT Sg
 *   H  → SEGMENT
 *   P  → SEGMENT
 *   Sg → SEGMENT
 *
 * Tokens esperados:
 *   - SEGMENT : cualquier bloque Base64URL (o vacío) entre puntos
 *   - DOT     : el carácter '.'
 *   - EOF     : fin de la entrada
 */
export class JwtSyntacticParser {
  constructor(tokens) {
    this.tokens = tokens || [];
    this.pos = 0;
    this.errors = [];

    this.grammar =
      'S  → J\n' +
      'J  → H "." P "." Sg\n' +
      'H  → SEGMENT\n' +
      'P  → SEGMENT\n' +
      'Sg → SEGMENT';
  }

  current() {
    return this.tokens[this.pos] || null;
  }

  /**
   * Consume un token del tipo esperado.
   * Si no coincide, registra un error pero NO lanza excepción,
   * para poder devolver un objeto sintáctico consistente.
   */
  expect(type, contexto) {
    const tok = this.current();
    if (!tok || tok.type !== type) {
      const where = contexto ? ` ${contexto}` : "";
      const found = tok ? `${tok.type} ('${tok.lexeme}')` : "EOF";
      this.errors.push(
        `Se esperaba token ${type}${where}, pero se encontró ${found} en posición ${this.pos}.`
      );
      return null;
    }
    this.pos++;
    return tok;
  }

  /**
   * Punto de entrada del parser: S → J
   */
  parse() {
    // S → J
    const jNode = this.parseJ();

    // Si todavía hay tokens además de EOF, error
    const extra = this.current();
    if (extra && extra.type !== "EOF") {
      this.errors.push(
        `Token inesperado '${extra.lexeme}' después de una estructura JWT válida.`
      );
    }

    // Si no se pudo construir J, no hay segmentos válidos
    let segments = null;
    let parseTree = null;
    let derivation = [];

    if (jNode && jNode.header && jNode.payload && jNode.signature) {
      segments = {
        headerB64: jNode.header.lexeme,
        payloadB64: jNode.payload.lexeme,
        signatureB64: jNode.signature.lexeme
      };

      // Derivación (similar a la que ya mostrabas en el front)
      derivation = [
        "S",
        "J",
        'H "." P "." Sg',
        'SEGMENT "." SEGMENT "." SEGMENT',
        `${segments.headerB64} "." ${segments.payloadB64} "." ${segments.signatureB64}`
      ];

      // Árbol de derivación
      parseTree = {
        symbol: "S",
        children: [
          {
            symbol: "J",
            rule: 'S → J',
            children: [
              {
                symbol: "H",
                rule: 'J → H "." P "." Sg',
                children: [{ symbol: "SEGMENT", value: segments.headerB64 }]
              },
              { symbol: '"."', value: "." },
              {
                symbol: "P",
                children: [{ symbol: "SEGMENT", value: segments.payloadB64 }]
              },
              { symbol: '"."', value: "." },
              {
                symbol: "Sg",
                children: [{ symbol: "SEGMENT", value: segments.signatureB64 }]
              }
            ]
          }
        ]
      };
    }

    const isValid = this.errors.length === 0;

    return {
      grammar: this.grammar,
      isValid,
      errors: this.errors,
      derivation,
      parseTree,
      asciiTree: this.generateAsciiTree(segments),
      segments
    };

  }

  /**
   * J → H "." P "." Sg
   */
  parseJ() {
    const header = this.parseH();
    this.expect("DOT", "después del HEADER");
    const payload = this.parseP();
    this.expect("DOT", "después del PAYLOAD");
    const signature = this.parseSg();
    this.expect("EOF", "al final del token");

    if (!header || !payload || !signature) {
      return null;
    }

    return { header, payload, signature };
  }

  /**
   * H → SEGMENT
   */
  parseH() {
    return this.expect("SEGMENT", "como HEADER");
  }

  /**
   * P → SEGMENT
   */
  parseP() {
    return this.expect("SEGMENT", "como PAYLOAD");
  }

  /**
   * Sg → SEGMENT
   */
  parseSg() {
    return this.expect("SEGMENT", "como SIGNATURE");
  }

  generateAsciiTree(segments) {
    if (!segments) return "Árbol no disponible (estructura inválida)\n";

    const h = segments.headerB64 || "???";
    const p = segments.payloadB64 || "???";
    const s = segments.signatureB64 || "???";

    return [
      "S",
      "└─ J",
      "   ├─ H  (SEGMENT) → HEADER",
      "   │      " + h,
      "   ├─ P  (SEGMENT) → PAYLOAD",
      "   │      " + p,
      "   └─ Sg (SEGMENT) → SIGNATURE",
      "          " + s,
    ].join("\n");
  }


}

/**
 * Función de ayuda para usar el parser fácilmente desde otros módulos.
 */
export function runSyntacticParserFromLexical(lexical) {
  // `lexical` viene como { table: [...] }
  const tokens =
    (lexical.table || []).map(row => ({
      type: row.token,   // SEGMENT, DOT, EOF
      lexeme: row.lexeme,
      estado: row.estado,
      index: row.index
    }));

  const parser = new JwtSyntacticParser(tokens);
  return parser.parse();
}


