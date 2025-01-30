import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import * as jwt from 'jsonwebtoken';
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}
 
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const token = this.extractTokenFromHeader(request);
    const authHeader = request.headers['authorization'];


    console.log('Extracted Token:', token); // Debugging token
 
    if (!token) {
      throw new UnauthorizedException('No token provided');
    }
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('No token provided');
    }
    try {
      const decoded = jwt.verify(token, 'bo86v7i51frFFI&V6udnpso85t6mz92o&$6FFI&V63#&PGH&(brjtexr#*PCV&B');
      request['user'] = decoded; 
      return true;
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }
 
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
 