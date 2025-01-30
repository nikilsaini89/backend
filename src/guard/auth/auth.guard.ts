import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { jwtConstants } from 'src/auth/constants';
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
      const decoded = jwt.verify(token, jwtConstants.secret);
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
 