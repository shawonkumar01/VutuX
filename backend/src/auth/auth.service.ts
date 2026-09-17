import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { randomUUID } from 'crypto';
import * as jwt from 'jsonwebtoken';

import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { AuthSession } from './entities/auth-session.entity';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,

    @InjectRepository(AuthSession)
    private readonly authSessionRepository: Repository<AuthSession>,
  ) {}

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

  async login(loginDto: LoginDto) {
    const user = await this.usersService.findByEmail(loginDto.email);

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const passwordMatches = await bcrypt.compare(
      loginDto.password,
      user.passwordHash,
    );

    if (!passwordMatches) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const payload = {
      sub: user.id,
      email: user.email,
      username: user.username,
    };

    // Access token
    const accessToken = await this.jwtService.signAsync(payload);

    // Refresh token
    const refreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

    if (!refreshSecret) {
      throw new Error('JWT_REFRESH_SECRET is not configured');
    }

    const jti = randomUUID();
    const familyId = randomUUID();

    const refreshToken = jwt.sign(
      {
        ...payload,
        jti,
        familyId,
      },
      refreshSecret,
      {
        expiresIn: '7d',
      },
    );

    // Store only the hash
    const refreshTokenHash = await bcrypt.hash(refreshToken, 12);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await this.authSessionRepository.save({
      userId: user.id,
      tokenId: jti,
      familyId,
      refreshTokenHash,
      expiresAt,
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  async refresh(refreshToken: string) {
    const refreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

    if (!refreshSecret) {
      throw new Error('JWT_REFRESH_SECRET is not configured');
    }

    let payload: {
      sub: string;
      email: string;
      username: string;
      jti: string;
      familyId: string;
    };

    // Verify the refresh token
    try {
      payload = jwt.verify(refreshToken, refreshSecret) as typeof payload;
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Use JTI-based direct lookup for active session (revokedAt IS NULL)
    const session = await this.authSessionRepository
      .createQueryBuilder('session')
      .where('session.userId = :userId', { userId: payload.sub })
      .andWhere('session.tokenId = :tokenId', { tokenId: payload.jti })
      .andWhere('session.revokedAt IS NULL')
      .getOne();

    if (!session) {
      // Token not found - check if it's a reused old token
      // Query to find any session with this tokenId (including revoked ones)
      const revokedSession = await this.authSessionRepository
        .createQueryBuilder('session')
        .where('session.userId = :userId', { userId: payload.sub })
        .andWhere('session.tokenId = :tokenId', { tokenId: payload.jti })
        .getOne();

      if (revokedSession) {
        // This specific token was previously issued and is now revoked - token reuse detected
        await this.authSessionRepository.update(
          {
            userId: payload.sub,
            familyId: payload.familyId,
          },
          {
            revokedAt: new Date(),
          },
        );
        throw new UnauthorizedException('Token reuse detected - all sessions invalidated');
      }

      throw new UnauthorizedException('Invalid refresh token');
    }

    // Verify the token hash matches
    const matches = await bcrypt.compare(
      refreshToken,
      session.refreshTokenHash,
    );

    if (!matches) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Check if session is revoked
    if (session.revokedAt) {
      throw new UnauthorizedException('Refresh token has been revoked');
    }

    // Check expiration
    if (session.expiresAt < new Date()) {
      await this.authSessionRepository.update(session.id, {
        revokedAt: new Date(),
      });
      throw new UnauthorizedException('Refresh token expired');
    }

    const newPayload = {
      sub: payload.sub,
      email: payload.email,
      username: payload.username,
    };

    // New access token
    const accessToken = await this.jwtService.signAsync(newPayload);

    // New refresh token with same familyId but new JTI
    const newJti = randomUUID();
    const newRefreshToken = jwt.sign(
      {
        ...newPayload,
        jti: newJti,
        familyId: payload.familyId,
      },
      refreshSecret,
      {
        expiresIn: '7d',
      },
    );

    // Hash new refresh token
    const newRefreshTokenHash = await bcrypt.hash(newRefreshToken, 12);

    const newExpiresAt = new Date();
    newExpiresAt.setDate(newExpiresAt.getDate() + 7);

    // Rotate the session with transaction to prevent race conditions
    await this.authSessionRepository.manager.transaction(async (transactionalEntityManager) => {
      // Re-fetch session with pessimistic write lock to prevent concurrent rotations
      const currentSession = await transactionalEntityManager.findOne(AuthSession, {
        where: { id: session.id },
        lock: { mode: 'pessimistic_write' },
      });

      if (!currentSession || currentSession.tokenId !== payload.jti) {
        throw new UnauthorizedException('Session was already rotated');
      }

      // Revoke the old session
      currentSession.revokedAt = new Date();
      await transactionalEntityManager.save(currentSession);

      // Create a new session with the same familyId
      const newSession = transactionalEntityManager.create(AuthSession, {
        userId: payload.sub,
        tokenId: newJti,
        familyId: payload.familyId,
        refreshTokenHash: newRefreshTokenHash,
        expiresAt: newExpiresAt,
        userAgent: session.userAgent,
        ipAddress: session.ipAddress,
      });

      await transactionalEntityManager.save(newSession);
    });

    return {
      accessToken,
      refreshToken: newRefreshToken,
    };
  }

  async logout(refreshToken: string) {
    const refreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

    if (!refreshSecret) {
      throw new Error('JWT_REFRESH_SECRET is not configured');
    }

    let payload: {
      sub: string;
      jti: string;
      familyId: string;
    };

    try {
      payload = jwt.verify(refreshToken, refreshSecret) as typeof payload;
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const session = await this.authSessionRepository.findOne({
      where: {
        userId: payload.sub,
        tokenId: payload.jti,
      },
    });

    if (session) {
      await this.authSessionRepository.update(session.id, {
        revokedAt: new Date(),
      });
    }
    // If session doesn't exist or is already revoked, silently succeed (idempotent)
  }
}
