import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { INestApplication } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as request from 'supertest';
import { ConflictException, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '../guard/auth/auth.guard';
describe('AuthController', () => {
  let app: INestApplication;
  const authService = { signup: jest.fn(), login: jest.fn() };
  const jwtService = { sign: jest.fn(), verifyAsync: jest.fn() };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: AuthService, useValue: authService },
        { provide: JwtService, useValue: jwtService },
        AuthGuard,
      ],
    })
      .overrideGuard(AuthGuard)
      .useValue(new AuthGuard(jwtService as any))
      .compile();

    app = module.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /auth/signup', () => {
    it('should register user successfully', async () => {
      const signupDto = {
        email: 'test@docquity.com',
        username: 'testuser',
        firstname: 'Amrit',
        lastname: 'Gupta',
        country_code: '+91',
        mobile_number: '9717211389',
        password: 'password123',
      };
      authService.signup.mockResolvedValue({
        message: 'User Registered Successfully',
      });

      const response = await request(app.getHttpServer())
        .post('/auth/signup')
        .send(signupDto)
        .expect(201);

      expect(response.body).toEqual({
        message: 'User Registered Successfully',
      });
    });

    it('should return 409 if email already exists', async () => {
      const signupDto = {
        email: 'existing@docquity.com',
        username: 'testuser',
        firstname: 'Amrit',
        lastname: 'Gupta',
        country_code: '+91',
        mobile_number: '9717211389',
        password: 'password123',
      };

      authService.signup.mockRejectedValue(new ConflictException('Conflict'));

      const response = await request(app.getHttpServer())
        .post('/auth/signup')
        .send(signupDto)
        .expect(409);

      expect(response.body.message).toBe('Conflict');
    });
  });

  describe('POST /auth/login', () => {
    it('should login user successfully', async () => {
      const loginDto = {
        email: 'test@docquity.com',
        password: 'password123',
      };

      authService.login.mockResolvedValue({
        message: 'User Login Successfully',
        access_token: 'mocked_token',
      });

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDto)
        .expect(201);

      expect(response.body).toEqual({
        message: 'User Login Successfully',
        access_token: 'mocked_token',
      });
    });

    it('should return 401 for invalid credentials', async () => {
      const loginDto = {
        email: 'test@docquity.com',
        password: 'wrongpassword',
      };

      authService.login.mockRejectedValue(
        new UnauthorizedException('Unauthorized'),
      );

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDto)
        .expect(401);

      expect(response.body.message).toBe('Unauthorized');
    });
  });

  // describe('GET /auth/validate-token', () => {
  //   it('should return 200 if token is valid', async () => {
  //     const validToken = 'valid.token.here';

  //     jwtService.verifyAsync.mockResolvedValue({ userId: 1 });

  //     const response = await request(app.getHttpServer())
  //       .get('/auth/validate-token')
  //       .set('Authorization', `Bearer ${validToken}`)
  //       .expect(200);

  //     expect(response.body).toEqual({ message: 'Token is valid' });
  //   });

  //   it('should return 401 if token is invalid', async () => {
  //     const invalidToken = 'invalid.token.here';

  //     jwtService.verifyAsync.mockRejectedValue(
  //       new UnauthorizedException('Invalid token'),
  //     );

  //     const response = await request(app.getHttpServer())
  //       .get('/auth/validate-token')
  //       .set('Authorization', `Bearer ${invalidToken}`)
  //       .expect(401);

  //     expect(response.body.message).toBe('Invalid token');
  //   });
  // });
});