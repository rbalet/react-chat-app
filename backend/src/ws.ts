import { WebSocketServer, WebSocket } from "ws";
import type { Server } from "http";

/** Map of userId → active WebSocket connections (a user may have multiple tabs). */
const connections = new Map<string, Set<WebSocket>>();

export function setupWebSocket(server: Server): void {
  const wss = new WebSocketServer({ server });

  wss.on("connection", (ws: WebSocket, req) => {
    const userId = req.url?.split("/chat/")[1];
    if (!userId) {
      ws.close(4001, "MISSING_USER_ID");
      return;
    }

    if (!connections.has(userId)) {
      connections.set(userId, new Set());
    }
    connections.get(userId)!.add(ws);

    ws.on("message", (raw: Buffer) => {
      let msg: { senderid?: string; receiverid?: string; chatId?: string };
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return;
      }

      if (!msg.chatId) msg.chatId = crypto.randomUUID();

      const payload = JSON.stringify(msg);
      const recipients = [msg.senderid, msg.receiverid].filter((r): r is string => Boolean(r));

      for (const recipientId of recipients) {
        const conns = connections.get(recipientId);
        if (!conns) continue;
        for (const conn of conns) {
          if (conn.readyState === WebSocket.OPEN) {
            conn.send(payload);
          }
        }
      }
    });

    ws.on("close", () => {
      const conns = connections.get(userId);
      if (!conns) return;
      conns.delete(ws);
      if (conns.size === 0) {
        connections.delete(userId);
      }
    });
  });
}
