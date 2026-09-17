import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuthSession } from './entities/auth-session.entity';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';

describe('AuthService - Refresh Token Rotation', () => {
  let service: AuthService;
  let authSessionRepository: Repository<AuthSession>;
  let jwtService: JwtService;
  let configService: ConfigService;

  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    username: 'testuser',
    displayName: 'Test User',
    passwordHash: 'hashedpassword',
    createdAt: new Date(),
  };

  const mockUsersService = {
    findByEmail: jest.fn().mockResolvedValue(mockUser),
    findByUsername: jest.fn().mockResolvedValue(null),
    create: jest.fn().mockResolvedValue(mockUser),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
        {
          provide: JwtService,
          useValue: {
            signAsync: jest.fn().mockResolvedValue('access-token'),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockReturnValue('test-refresh-secret'),
          },
        },
        {
          provide: getRepositoryToken(AuthSession),
          useClass: Repository,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    authSessionRepository = module.get<Repository<AuthSession>>(
      getRepositoryToken(AuthSession),
    );
    jwtService = module.get<JwtService>(JwtService);
    configService = module.get<ConfigService>(ConfigService);

    // Mock repository methods
    jest.spyOn(authSessionRepository, 'save').mockImplementation(async (entity) => {
      if (Array.isArray(entity)) {
        return entity as any;
      }
      return { ...entity, id: 'session-id', createdAt: new Date(), updatedAt: new Date() } as any;
    });
    jest.spyOn(authSessionRepository, 'findOne').mockResolvedValue(null);
    jest.spyOn(authSessionRepository, 'update').mockResolvedValue({ affected: 1 } as any);
    jest.spyOn(authSessionRepository, 'create').mockImplementation((entity) => entity as any);
  });

  describe('Login', () => {
    it('should create a session with unique jti and familyId', async () => {
      const loginDto = {
        email: 'test@example.com',
        password: 'password123',
      };

      const result = await service.login(loginDto);

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');

      const saveSpy = jest.spyOn(authSessionRepository, 'save');
      expect(saveSpy).toHaveBeenCalled();

      const savedSession = saveSpy.mock.calls[0][0];
      expect(savedSession).toHaveProperty('tokenId');
      expect(savedSession).toHaveProperty('familyId');
      expect(savedSession.tokenId).toBeDefined();
      expect(savedSession.familyId).toBeDefined();
      expect(savedSession.tokenId).not.toBe(savedSession.familyId);
    });
  });

  describe('Refresh Token Rotation', () => {
    let mockSession: AuthSession;
    let refreshToken: string;
    let refreshSecret: string;

    beforeEach(() => {
      refreshSecret = 'test-refresh-secret';
      const jti = 'token-a';
      const familyId = 'family-123';

      refreshToken = jwt.sign(
        {
          sub: mockUser.id,
          email: mockUser.email,
          username: mockUser.username,
          jti,
          familyId,
        },
        refreshSecret,
        { expiresIn: '7d' },
      );

      mockSession = {
        id: 'session-id',
        userId: mockUser.id,
        tokenId: jti,
        familyId,
        refreshTokenHash: bcrypt.hashSync(refreshToken, 12),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        revokedAt: null,
        userAgent: null,
        ipAddress: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
    });

    it('should rotate refresh token - revoke old session and create new one', async () => {
      // Mock finding the active session
      jest.spyOn(authSessionRepository, 'createQueryBuilder').mockReturnValue({
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getOne: jest.fn().mockResolvedValue(mockSession),
      } as any);

      // Mock transaction
      const mockTransaction = jest.fn().mockImplementation(async (callback) => {
        const mockTransactionalEntityManager = {
          findOne: jest.fn().mockResolvedValue(mockSession),
          save: jest.fn().mockResolvedValue({ ...mockSession, revokedAt: new Date() }),
          create: jest.fn().mockImplementation((entity) => entity),
        };
        await callback(mockTransactionalEntityManager);
      });

      jest.spyOn(authSessionRepository.manager, 'transaction').mockImplementation(mockTransaction);

      const result = await service.refresh(refreshToken);

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(result.refreshToken).not.toBe(refreshToken);
    });

    it('should detect token reuse and revoke entire family', async () => {
      // Mock no active session found
      jest.spyOn(authSessionRepository, 'createQueryBuilder').mockReturnValue({
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getOne: jest.fn()
          .mockResolvedValueOnce(null) // First query (active session)
          .mockResolvedValueOnce(mockSession) // Second query (revoked session - reuse detected)
          .mockResolvedValueOnce(null) // Third query (for family check)
          .mockResolvedValueOnce(mockSession), // Fourth query (family exists)
      } as any);

      await expect(service.refresh(refreshToken)).rejects.toThrow(
        'Token reuse detected - all sessions invalidated',
      );

      const updateSpy = jest.spyOn(authSessionRepository, 'update');
      expect(updateSpy).toHaveBeenCalledWith(
        {
          userId: mockUser.id,
          familyId: mockSession.familyId,
        },
        {
          revokedAt: expect.any(Date),
        },
      );
    });

    it('should reject invalid refresh token', async () => {
      // Mock no session found (not even a revoked one)
      jest.spyOn(authSessionRepository, 'createQueryBuilder').mockReturnValue({
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getOne: jest.fn().mockResolvedValue(null),
      } as any);

      await expect(service.refresh('invalid-token')).rejects.toThrow(
        'Invalid refresh token',
      );
    });

    it('should reject revoked session', async () => {
      const revokedSession = { ...mockSession, revokedAt: new Date() };

      jest.spyOn(authSessionRepository, 'createQueryBuilder').mockReturnValue({
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getOne: jest.fn().mockResolvedValue(revokedSession),
      } as any);

      await expect(service.refresh(refreshToken)).rejects.toThrow(
        'Refresh token has been revoked',
      );
    });

    it('should reject expired session', async () => {
      const expiredSession = { ...mockSession, expiresAt: new Date(Date.now() - 1000) };

      jest.spyOn(authSessionRepository, 'createQueryBuilder').mockReturnValue({
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getOne: jest.fn().mockResolvedValue(expiredSession),
      } as any);

      await expect(service.refresh(refreshToken)).rejects.toThrow(
        'Refresh token expired',
      );
    });
  });

  describe('Logout', () => {
    it('should revoke session', async () => {
      const jti = 'token-a';
      const familyId = 'family-123';
      const refreshToken = jwt.sign(
        {
          sub: mockUser.id,
          jti,
          familyId,
        },
        'test-secret',
        { expiresIn: '7d' },
      );

      const mockSession = {
        id: 'session-id',
        userId: mockUser.id,
        tokenId: jti,
        familyId,
        refreshTokenHash: 'hash',
        expiresAt: new Date(),
        revokedAt: null,
      };

      jest.spyOn(authSessionRepository, 'findOne').mockResolvedValue(mockSession as any);

      await service.logout(refreshToken);

      const updateSpy = jest.spyOn(authSessionRepository, 'update');
      expect(updateSpy).toHaveBeenCalledWith(mockSession.id, {
        revokedAt: expect.any(Date),
      });
    });

    it('should be idempotent - succeed if session already revoked', async () => {
      const jti = 'token-a';
      const familyId = 'family-123';
      const refreshToken = jwt.sign(
        {
          sub: mockUser.id,
          jti,
          familyId,
        },
        'test-secret',
        { expiresIn: '7d' },
      );

      jest.spyOn(authSessionRepository, 'findOne').mockResolvedValue(null);

      await expect(service.logout(refreshToken)).resolves.not.toThrow();
    });
  });
});
