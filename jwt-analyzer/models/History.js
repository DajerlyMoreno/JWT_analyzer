// models/History.js
import {
  DynamoDBClient
} from "@aws-sdk/client-dynamodb";

import {
  DynamoDBDocumentClient,
  PutCommand,
  ScanCommand,
  DeleteCommand
} from "@aws-sdk/lib-dynamodb";

const client = new DynamoDBClient({});
const ddb = DynamoDBDocumentClient.from(client);

const TABLE = "HistoryTable"; // Nombre de la tabla

// Crear registro
export async function historyCreate(data) {
  const item = {
    id: Date.now().toString(),   // ID única
    type: data.type,
    token: data.token,
    header: data.header || null,
    payload: data.payload || null,
    secret: data.secret || null,
    algorithm: data.algorithm || null,
    createdAt: new Date().toISOString()
  };

  await ddb.send(new PutCommand({
    TableName: TABLE,
    Item: item
  }));

  return item;
}

// Obtener todo el historial
export async function historyFindAll() {
  const result = await ddb.send(new ScanCommand({
    TableName: TABLE
  }));

  return result.Items || [];
}

// Borrar todos los registros
export async function historyClear() {
  const items = await historyFindAll();

  for (const item of items) {
    await ddb.send(new DeleteCommand({
      TableName: TABLE,
      Key: { id: item.id }
    }));
  }

  return items.length;
}
