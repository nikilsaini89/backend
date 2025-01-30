import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { JwtModule } from '@nestjs/jwt';
@Module({
  imports: [TypeOrmModule.forFeature([User]),

  JwtModule.register({
    global: true,
    secret: 'bo86v7i51frFFI&V6udnpso85t6mz92o&$6FFI&V63#&PGH&(brjtexr#*PCV&B',
    signOptions: { expiresIn: '1800s' },
  }),

  ],
  providers: [AuthService],
  controllers: [AuthController]
})
export class AuthModule {}
