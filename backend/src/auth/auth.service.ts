import {
  ConflictException,
  Injectable,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { RegisterDto } from './dto/register.dto';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(private readonly usersService: UsersService) {}

  async register(registerDto: RegisterDto) {
    const existingEmail = await this.usersService.findByEmail(
      registerDto.email,
    );

    if (existingEmail) {
      throw new ConflictException('Email already exists');
    }

    const existingUsername = await this.usersService.findByUsername(
      registerDto.username,
    );

    if (existingUsername) {
      throw new ConflictException('Username already exists');
    }

    const passwordHash = await bcrypt.hash(registerDto.password, 12);

    const user = await this.usersService.create({
      username: registerDto.username,
      displayName: registerDto.displayName,
      email: registerDto.email,
      passwordHash,
    });

    return {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      email: user.email,
      createdAt: user.createdAt,
    };
  }
}