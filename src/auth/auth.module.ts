import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule , JwtService} from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { UsersModule } from '../users/users.module';
import { LocalStrategy } from './local.strategy';
import { AuthController } from './auth.controller';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.register({
      secret: process.env.jwt_secret, // replace with your secret key
      signOptions: { expiresIn: '1h' }, // token expiration time
    }),
  ],
  providers: [AuthService, LocalStrategy],
  exports: [AuthService],
  controllers: [AuthController], // Export the service if needed in other modules
})
export class AuthModule {}
