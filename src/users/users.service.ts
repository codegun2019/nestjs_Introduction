import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

// This should be a real class/interface representing a user entity
export type User = any;

@Injectable()
export class UsersService {
  private readonly users = [
    {
      userId: 1,
      username: 'john',
      // Plain text password
      password: 'changeme',
    },
    {
      userId: 2,
      username: 'maria',
      // Plain text password
      password: 'guess',
    },
  ];

  constructor(private readonly jwtService: JwtService) {}

  async findOne(username: string): Promise<User | undefined> {
    const user = this.users.find((user) => user.username === username);

    if (user) {
      console.log('User Password (Plain Text):', user.password);
      // เข้ารหัสรหัสผ่านและ console.log รหัสที่เข้ารหัส
      const hashedPassword = await this.hashPassword(user.password);
      console.log('User Password (Hashed):', hashedPassword);
    }

    return user;
  }

  async hashPassword(password: string): Promise<string> {
    const saltRounds = 10;
    return bcrypt.hash(password, saltRounds);
  }

  async signIn(
    username: string,
    password: string,
  ): Promise<{ access_token: string }> {
    const user = await this.findOne(username);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // ตรวจสอบรหัสผ่าน
    const isPasswordValid = await this.verifyPassword(password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // สร้าง token
    const payload = { sub: user.userId, username: user.username };
    const token = await this.jwtService.signAsync(payload);

    // ส่งค่า token กลับ
    return {
      access_token: token,
    };
  }

  private async verifyPassword(
    plainTextPassword: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(plainTextPassword, hashedPassword);
  }
}
