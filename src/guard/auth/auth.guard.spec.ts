import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthGuard } from './auth.guard';
import * as jwt from 'jsonwebtoken';

describe('AuthGuard', () => {
  let authGuard: AuthGuard;
  let jwtService: JwtService;

  beforeEach(() => {
    jwtService = new JwtService({});
    authGuard = new AuthGuard(jwtService);
  });

  function mockExecutionContext(authHeader?: string): ExecutionContext {
    return {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: { authorization: authHeader },
          user: null,
        }),
      }),
    } as unknown as ExecutionContext;
  }

  it('should allow access when a valid token is provided', async () => {
    const validToken = jwt.sign({ userId: 1 }, 'test-secret');
    const context = mockExecutionContext(`Bearer ${validToken}`);

    // 🔹 Fix: Use mockImplementation() to return a proper JwtPayload
    jest.spyOn(jwt, 'verify').mockImplementation(() => ({ userId: 1 } as jwt.JwtPayload));

    await expect(authGuard.canActivate(context)).resolves.toBe(true);
  });

  it('should throw UnauthorizedException when no token is provided', async () => {
    const context = mockExecutionContext(undefined);
    await expect(authGuard.canActivate(context)).rejects.toThrow(UnauthorizedException);
  });

  it('should throw UnauthorizedException when token is invalid', async () => {
    const invalidToken = 'invalid.token.here';
    const context = mockExecutionContext(`Bearer ${invalidToken}`);

    jest.spyOn(jwt, 'verify').mockImplementation(() => {
      throw new Error('Invalid token');
    });

    await expect(authGuard.canActivate(context)).rejects.toThrow(UnauthorizedException);
  });

  it('should assign decoded token to request.user', async () => {
    const validToken = jwt.sign({ userId: 2 }, 'test-secret');
    
    // Create a request object that allows modifications
    const request = { headers: { authorization: `Bearer ${validToken}` }, user: null };
  
    const context = {
      switchToHttp: () => ({
        getRequest: () => request,
      }),
    } as unknown as ExecutionContext;
  
    // Mock jwt.verify to return a valid payload
    jest.spyOn(jwt, 'verify').mockImplementation(() => ({ userId: 2 } as jwt.JwtPayload));
  
    const result = await authGuard.canActivate(context);
    expect(result).toBe(true);
  
    // Ensure request.user is set
    expect(request.user).toEqual({ userId: 2 });
  });
  
});
