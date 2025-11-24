// src/services/JsonParserService.js

/**
 * Parser JSON recursivo–descendente para objetos JSON sencillos,
 * pensado para header y payload de JWT.
 *
 * Soporta:
 *  - Objetos: { "k": v, ... }
 *  - Arrays:  [ v1, v2, ... ]
 *  - Strings: "texto"
 *  - Números: 123, -10, 3.14, 1e3, etc.
 *  - Literales: true, false, null
 *
 * Cada método devuelve:
 *  { value, tree }
 * donde `value` es el valor JS normal
 * y `tree` es un nodo del árbol sintáctico.
 */

export class JsonParser {
  constructor(input) {
    this.input = input;
    this.pos = 0;
    this.len = input.length;
  }

  /** API principal: parsea un objeto JSON completo */
  parseRootObject() {
    this._skipWs();
    const node = this._parseObject();
    this._skipWs();

    if (this.pos !== this.len) {
      throw new Error(
        `JSON con datos extra después del objeto en la posición ${this.pos}`
      );
    }

    return {
      value: node.value,
      tree: node.tree
    };
  }

  // ========== Utilidades internas ==========

  _currentChar() {
    return this.input[this.pos];
  }

  _skipWs() {
    while (this.pos < this.len) {
      const c = this.input[this.pos];
      if (c === " " || c === "\n" || c === "\t" || c === "\r") {
        this.pos++;
      } else {
        break;
      }
    }
  }

  _expectChar(ch) {
    if (this._currentChar() !== ch) {
      throw new Error(
        `Se esperaba '${ch}' en la posición ${this.pos}, encontrado '${this._currentChar() || "EOF"}'`
      );
    }
    this.pos++;
  }

  _matchKeyword(keyword) {
    if (this.input.slice(this.pos, this.pos + keyword.length) === keyword) {
      this.pos += keyword.length;
      return true;
    }
    return false;
  }

  // ========== Parseo de estructuras ==========

  _parseObject() {
    this._expectChar("{");
    this._skipWs();

    const obj = {};
    const children = [];

    // Objeto vacío
    if (this._currentChar() === "}") {
      this.pos++;
      return {
        value: obj,
        tree: {
          type: "Object",
          label: "OBJECT",
          children
        }
      };
    }

    // Uno o más pares "clave: valor"
    while (true) {
      const pair = this._parsePair();
      obj[pair.key] = pair.value;
      children.push(pair.tree);

      this._skipWs();
      const c = this._currentChar();

      if (c === ",") {
        this.pos++;
        this._skipWs();
        continue;
      }

      if (c === "}") {
        this.pos++;
        break;
      }

      throw new Error(
        `Se esperaba ',' o '}' en la posición ${this.pos}, encontrado '${c ||
          "EOF"}'`
      );
    }

    return {
      value: obj,
      tree: {
        type: "Object",
        label: "OBJECT",
        children
      }
    };
  }

  _parsePair() {
    this._skipWs();
    const keyNode = this._parseStringNode(); // { value, tree }

    this._skipWs();
    this._expectChar(":");
    this._skipWs();

    const valueNode = this._parseValue();

    return {
      key: keyNode.value,
      value: valueNode.value,
      tree: {
        type: "Member",
        label: "PAIR",
        children: [keyNode.tree, valueNode.tree]
      }
    };
  }

  _parseArray() {
    this._expectChar("[");
    this._skipWs();

    const arr = [];
    const children = [];

    if (this._currentChar() === "]") {
      this.pos++;
      return {
        value: arr,
        tree: {
          type: "Array",
          label: "ARRAY",
          children
        }
      };
    }

    while (true) {
      const valueNode = this._parseValue();
      arr.push(valueNode.value);
      children.push(valueNode.tree);

      this._skipWs();
      const c = this._currentChar();

      if (c === ",") {
        this.pos++;
        this._skipWs();
        continue;
      }

      if (c === "]") {
        this.pos++;
        break;
      }

      throw new Error(
        `Se esperaba ',' o ']' en la posición ${this.pos}, encontrado '${c ||
          "EOF"}'`
      );
    }

    return {
      value: arr,
      tree: {
        type: "Array",
        label: "ARRAY",
        children
      }
    };
  }

  _parseValue() {
    this._skipWs();
    const c = this._currentChar();

    if (c === "{") return this._parseObject();
    if (c === "[") return this._parseArray();
    if (c === '"') return this._parseStringNode();
    if (c === "-" || (c >= "0" && c <= "9")) return this._parseNumberNode();

    // true / false / null
    if (this._matchKeyword("true")) {
      return {
        value: true,
        tree: { type: "Literal", label: "true", children: [] }
      };
    }
    if (this._matchKeyword("false")) {
      return {
        value: false,
        tree: { type: "Literal", label: "false", children: [] }
      };
    }
    if (this._matchKeyword("null")) {
      return {
        value: null,
        tree: { type: "Literal", label: "null", children: [] }
      };
    }

    throw new Error(
      `Valor JSON inesperado en la posición ${this.pos}: '${c || "EOF"}'`
    );
  }

  _parseStringNode() {
    this._expectChar('"');
    let result = "";

    while (this.pos < this.len) {
      const c = this._currentChar();
      if (c === '"') {
        this.pos++;
        break;
      }
      if (c === "\\") {
        // Soporte básico de escapes: \" \\ \n \t
        this.pos++;
        const esc = this._currentChar();
        if (esc === '"' || esc === "\\" || esc === "/") {
          result += esc;
        } else if (esc === "n") {
          result += "\n";
        } else if (esc === "t") {
          result += "\t";
        } else if (esc === "r") {
          result += "\r";
        } else {
          // Para simplificar, no manejamos \uXXXX aquí
          result += esc;
        }
        this.pos++;
      } else {
        result += c;
        this.pos++;
      }
    }

    return {
      value: result,
      tree: {
        type: "String",
        label: `"${result}"`,
        children: []
      }
    };
  }

  _parseNumberNode() {
    let start = this.pos;
    let c = this._currentChar();

    if (c === "-") {
      this.pos++;
      c = this._currentChar();
    }

    if (!(c >= "0" && c <= "9")) {
      throw new Error(`Número inválido en la posición ${this.pos}`);
    }

    // parte entera
    if (c === "0") {
      this.pos++;
    } else {
      while (this.pos < this.len) {
        c = this._currentChar();
        if (c >= "0" && c <= "9") this.pos++;
        else break;
      }
    }

    // parte decimal
    if (this._currentChar() === ".") {
      this.pos++;
      c = this._currentChar();
      if (!(c >= "0" && c <= "9")) {
        throw new Error(
          `Número decimal inválido en la posición ${this.pos}`
        );
      }
      while (this.pos < this.len) {
        c = this._currentChar();
        if (c >= "0" && c <= "9") this.pos++;
        else break;
      }
    }

    // exponente
    c = this._currentChar();
    if (c === "e" || c === "E") {
      this.pos++;
      c = this._currentChar();
      if (c === "+" || c === "-") {
        this.pos++;
      }
      c = this._currentChar();
      if (!(c >= "0" && c <= "9")) {
        throw new Error(
          `Exponente inválido en la posición ${this.pos}`
        );
      }
      while (this.pos < this.len) {
        c = this._currentChar();
        if (c >= "0" && c <= "9") this.pos++;
        else break;
      }
    }

    const raw = this.input.slice(start, this.pos);
    const num = Number(raw);

    if (Number.isNaN(num)) {
      throw new Error(`Número inválido: '${raw}'`);
    }

    return {
      value: num,
      tree: {
        type: "Number",
        label: raw,
        children: []
      }
    };
  }
}

/**
 * Función de conveniencia para usar desde otros servicios.
 * Recibe un string JSON y devuelve:
 *  { value: objetoJS, tree: arbolSintactico }
 */
export function parseJsonObjectWithTree(jsonString) {
  const parser = new JsonParser(jsonString);
  return parser.parseRootObject();
}
