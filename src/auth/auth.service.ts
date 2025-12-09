import { Injectable, ConflictException, UnauthorizedException, NotFoundException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { User } from '../schemas/user.schema';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto): Promise<{ message: string; user: any; token: string }> {
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

    const { password: _, ...userWithoutPassword } = user.toObject();

    return {
      message: 'Đăng ký người dùng thành công',
      user: userWithoutPassword as any,
      token,
    };
  }

  async login(loginDto: LoginDto): Promise<{ message: string; user: any; token: string }> {
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

    const { password: _, ...userWithoutPassword } = user.toObject();

    return {
      message: 'Đăng nhập thành công',
      user: userWithoutPassword as any,
      token,
    };
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
  
  async validateUserById(userId: string): Promise<User | null> {
    return this.userModel.findById(userId);
  }
}