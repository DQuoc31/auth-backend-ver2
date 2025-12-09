import { Injectable, ConflictException, UnauthorizedException, NotFoundException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { User } from '../schemas/user.schema';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async register(registerDto: RegisterDto): Promise<{ message: string; user: any; token: string; refreshToken?: string }> {
    const {email, password } = registerDto;

    const existingUser = await this.userModel.findOne({ email });
    if (existingUser) {
      throw new ConflictException('Người dùng với email này đã tồn tại');
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await this.userModel.create({
      email,
      password: hashedPassword,
    });

    const token = this.generateToken(user);
    const refreshToken = this.generateRefreshToken(user);

    // save refresh token on user
    user.refreshToken = refreshToken;
    await user.save();

    const { password: _, ...userWithoutPassword } = user.toObject();

    return {
      message: 'Đăng ký người dùng thành công',
      user: userWithoutPassword as any,
      token,
      refreshToken,
    };
  }

  async login(loginDto: LoginDto): Promise<{ message: string; user: any; token: string; refreshToken?: string }> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Email hoặc mật khẩu không đúng');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Email hoặc mật khẩu không đúng');
    }

    const token = this.generateToken(user);
    const refreshToken = this.generateRefreshToken(user);

    user.refreshToken = refreshToken;
    await user.save();

    const { password: _, ...userWithoutPassword } = user.toObject();

    return {
      message: 'Đăng nhập thành công',
      user: userWithoutPassword as any,
      token,
      refreshToken,
    };
  }

  async refreshToken(refreshToken: string) {
    if (!refreshToken) throw new BadRequestException('Refresh token required');

    const refreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET') || this.configService.get<string>('JWT_SECRET');
    try {
      const payload: any = this.jwtService.verify(refreshToken, { secret: refreshSecret });
      const user = await this.userModel.findById(payload.sub);
      if (!user) throw new UnauthorizedException('Invalid refresh token');
      if (!user.refreshToken || user.refreshToken !== refreshToken) {
        throw new UnauthorizedException('Refresh token does not match');
      }

      // generate new tokens
      const token = this.generateToken(user);
      const newRefresh = this.generateRefreshToken(user);
      user.refreshToken = newRefresh;
      await user.save();

      return { token, refreshToken: newRefresh, user: { _id: user._id, email: user.email, createdAt: user.createdAt } };
    } catch (err) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async getProfile(userId: string): Promise<any> {
    const user = await this.userModel.findById(userId).select('-password');
    if (!user) {
      throw new NotFoundException('Người dùng không tồn tại');
    }
    return user.toObject();
  }

  private generateToken(user: User): string {
    const payload = { 
      sub: user._id.toString(), 
      email: user.email 
    };
    return this.jwtService.sign(payload);
  }
  private generateRefreshToken(user: User): string {
    const payload = { sub: user._id.toString(), email: user.email };
    const refreshSecretRaw = this.configService.get<string>('JWT_REFRESH_SECRET') || this.configService.get<string>('JWT_SECRET')
    if (!refreshSecretRaw) {
      throw new Error('Refresh token secret is not configured')
    }
    const refreshSecret = String(refreshSecretRaw)
    const expiresIn = this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') || '7d'
    // ensure the expiresIn value matches the jwt.SignOptions type
    const options: jwt.SignOptions = { expiresIn: expiresIn as unknown as jwt.SignOptions['expiresIn'] }
    // use jsonwebtoken directly to sign with the refresh secret and avoid JwtService constructor typing issues
    return jwt.sign(payload, refreshSecret as jwt.Secret, options)
  }
  
  async validateUserById(userId: string): Promise<User | null> {
    return this.userModel.findById(userId);
  }
}