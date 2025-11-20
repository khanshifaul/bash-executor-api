export interface JwtPayload {
  sub: string;
  email: string;
  role?: string;
  type?: string;
  permissions?: string[];
  iat?: number;
  exp?: number;
  rememberMe?: boolean;
  sessionId?: string;
  tokenFamily?: string;
}
