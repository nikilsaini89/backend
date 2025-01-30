import {IsEmail, IsNotEmpty, MinLength} from '@nestjs/class-validator';

export class LoginupDto {
    @IsEmail()
    email: string;
  
    @MinLength(8)
    password: string;
  }
  