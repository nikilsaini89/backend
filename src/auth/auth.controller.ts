import { Body, Controller, Get, Post, UseGuards, Request, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginupDto } from './dto/login.dto';
import { User } from './entities/user.entity';
import { AuthGuard } from '../guard/auth/auth.guard';

@Controller('auth')
export class AuthController {

    constructor(private readonly authService:AuthService){}

    @Post('signup')
    async signup(@Body() signupDto : SignupDto){
        return this.authService.signup(signupDto)
    }
    @Post('login')
    async login(@Body() LoginupDto : LoginupDto){
        return this.authService.login(LoginupDto)
    }

    @UseGuards(AuthGuard)
    @Get('dashboard')
    async dashboard():  Promise<User[]>{
        return this.authService.getTable()
    }
    @UseGuards(AuthGuard)
    @Get('verify-token')
    async verifytoken(@Request() req){
        const user = req.user;
        if (user) {
          return { message: 'Token is valid' };
        } else {
          throw new UnauthorizedException('Invalid token');
        }
    
    }
}
