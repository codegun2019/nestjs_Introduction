import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { UsersService } from './users.service';

@Module({
  imports: [JwtModule], // Import JwtModule here
  providers: [UsersService],
  exports: [UsersService], // Export UsersService if needed in other modules
})
export class UsersModule {}