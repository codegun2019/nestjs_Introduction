import { Controller, Post, Body, Res } from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(
    @Body() credentials: { username: string; password: string },
    @Res() response: Response,
  ) {
    try {
      const token = await this.authService.signIn(
        credentials.username,
        credentials.password,
      );
      // Set the token as an HTTP-only cookie
      response.cookie('token', token.access_token, { httpOnly: true });

      // Send a success response with the token
      response.send({ message: 'Login successful', token: token.access_token });
    } catch (error) {
      // Handle authentication failure
      response.status(401).send({ message: 'Authentication failed' });
    }
  }
}
