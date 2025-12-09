import { IsEmail, IsString, IsNotEmpty } from 'class-validator';

export class LoginDto {
  @IsEmail({}, { message: 'Vui lòng cung cấp địa chỉ email hợp lệ' })
  @IsNotEmpty({ message: 'Email là bắt buộc' })
  email: string;

  @IsString()
  @IsNotEmpty({ message: 'Mật khẩu là bắt buộc' })
  password: string;
}