import type { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { JWT_PUBLIC_KEY } from "./config";

// Extend Express Request to include userId
declare global {
  namespace Express {
    interface Request {
      userId?: string;
    }
  }
}

export function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const token = req.headers['authorization'];
  if (!token) {
    res.status(401).json({ error: 'Unauthorized' });
    return; // ✅ stop execution
  }

  try {
    const decoded = jwt.verify(token, JWT_PUBLIC_KEY) as jwt.JwtPayload;

    if (!decoded || typeof decoded.sub !== 'string') {
      res.status(401).json({ error: 'Unauthorized' });
      return; 
    }

    req.userId = decoded.sub;
    next(); 
  } catch (err) {
    console.error("JWT verification error:", err);
    res.status(401).json({ error: 'Invalid token' });
  }
}
