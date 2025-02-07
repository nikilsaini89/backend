import { ConflictException, Injectable, BadRequestException,UnauthorizedException, NotFoundException } from '@nestjs/common';
import { InjectRepository, } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { SignupDto } from './dto/signup.dto';
import { LoginupDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        private jwtService: JwtService
    ) {}

    async signup(signupDto: SignupDto): Promise<{ message: string }> {
        const { email, username, password, ...otherDetails } = signupDto;
        
        // console.log('signupDto', signupDto);
        const emailExists = await this.userRepository.findOne({ where: { email } });
        if (emailExists) {
            throw new ConflictException({
                field: 'email',
                message: 'Email already exists',
            });
        }

        const usernameExists = await this.userRepository.findOne({ where: { username } });
        if (usernameExists) {
            throw new ConflictException({
                field: 'username',
                message: 'Username already exists',
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // console.log('otherDetails', otherDetails);
        const user = this.userRepository.create({
            ...otherDetails,
            email,
            username,
            password: hashedPassword,
        });
        // console
        await this.userRepository.save(user);

        return { message: 'User Registered Successfully' };
    }


    async login(LoginupDto: LoginupDto): Promise<{ message: string, access_token: string }> {
        const { email, password } = LoginupDto;

        const userExists = await this.userRepository.findOne({ where: { email } });
        if (!userExists) {
            throw new NotFoundException({
                field: 'email',
                message: 'User does not exists',
            });
        }

        const valid = await bcrypt.compare(password, userExists.password);
        if (valid === false) {
            throw new BadRequestException({
                field: 'password',
                message: 'Wrong Password',
            });
        }

        const payload = { sub: userExists.id, email: userExists.email };
        return {
            message: "Logged in Sucssfully",
            access_token: await this.jwtService.signAsync(payload),
        };
    }
    async getTable(): Promise<User[]> {
        try {
            return await this.userRepository.find({
                select: ['firstname', 'lastname', 'username', 'email', 'mobile_number']
            });
        } catch (error) {
            console.error('Error fetching user table:', error);
            throw new Error('Failed to fetch user table. Please try again later.');
        }
    }
    
}
