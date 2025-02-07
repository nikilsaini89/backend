import { Repository } from "typeorm";
import { AuthService } from "./auth.service";
import { User } from "./entities/user.entity";
import { JwtService } from "@nestjs/jwt";
import { Test, TestingModule } from "@nestjs/testing";
import { getRepositoryToken } from "@nestjs/typeorm";
import { first, last } from "rxjs";
import { count } from "console";
import * as bcrypt from 'bcrypt';
import { BadRequestException, ConflictException, NotFoundException } from "@nestjs/common";
import { sign } from "crypto";

describe.only('AuthService', () => {
  let authService: AuthService;
  let userRepository: Repository<User>;
  let jwtService: JwtService;

  const mockUserRepository = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
  };

  const mockJwtService = {
    signAsync: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(User),
          useValue: mockUserRepository,
        },
        {
          provide: JwtService,
          useValue: mockJwtService
        },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    jwtService = module.get<JwtService>(JwtService);
  });

  describe.only('signup', () => {
    const signupDto = {
      firstname: 'temp',
      lastname: 'temp',
      email: 'temp@docquity.com',
      username: 'temp',
      password: 'Sys@1234',
      country_code: '91',
      mobile_number: '1234567890',
    };

    it('should successfully register a user', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);
      jest.spyOn(bcrypt, 'hashSync').mockReturnValue('hashedPassword');
      jest.spyOn(userRepository, 'create').mockReturnValue({
        ...signupDto,
        password: 'hashedPassword',
      } as any);
      jest.spyOn(userRepository, 'save').mockResolvedValue({
        ...signupDto,
        password: 'hashedPassword',
      } as any);

      const result = await authService.signup(signupDto);

      expect(result).toEqual({ message: 'User Registered Successfully' });
      expect(userRepository.create).toHaveBeenCalledTimes(1);
      expect(userRepository.save).toHaveBeenCalledTimes(1);
    });

    it('should throw ConflictException if email exists', async () => {
      jest
        .spyOn(userRepository, 'findOne')
        .mockResolvedValue({ id: 1 } as User);

      await expect(authService.signup(signupDto)).rejects.toThrow(
        ConflictException,
      );
    });

    it('should throw ConflictException if username exists', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValueOnce(null); // No user found by email
      jest
        .spyOn(userRepository, 'findOne')
        .mockResolvedValueOnce({ id: 1 } as User); // Username exists

      await expect(authService.signup(signupDto)).rejects.toThrow(
        ConflictException,
      );
    });


  });


  describe('login', () => {
    const loginDto = {
      email: 'test@docquity.com',
      password: 'password123',
    };
    it('should return user not found', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);

      await expect(authService.login(loginDto)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should return invalid credentials', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue({ id: 1 } as User);

      jest.spyOn(bcrypt, 'compare').mockReturnValue(false);

      await expect(authService.login(loginDto)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should log in successfully and return an access token', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue({ id: 1 } as User);

      jest.spyOn(bcrypt, 'compare').mockReturnValue(true);
      jest.spyOn(jwtService, 'signAsync').mockResolvedValue('fake-jwt-token');

      // Call the method you're testing (replace 'login' with the actual method name)
      const result = await authService.login(loginDto);

      // Assert that the response contains the expected values
      expect(result.message).toBe("Logged in Sucssfully");
      expect(result.access_token).toBe('fake-jwt-token');
    });
    
  });

  describe('login', () => {

    
  });


  
});
