import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    // Bước 1: Cấu hình ConfigModule toàn cục
    ConfigModule.forRoot({
      isGlobal: true,      // Có thể sử dụng ở mọi nơi
      envFilePath: '.env', // Đường dẫn file environment
    }),
    
    // Bước 2: Kết nối MongoDB (async configuration)
    MongooseModule.forRootAsync({
      imports: [ConfigModule], // Import ConfigModule để sử dụng ConfigService
      useFactory: async (configService: ConfigService) => ({
        uri: configService.get<string>('MONGODB_URI') || 'mongodb://localhost:27017/auth-app',
      }),
      inject: [ConfigService], // Inject ConfigService vào useFactory
    }),
    
    // Bước 3: Import AuthModule
    AuthModule,
  ],
})
export class AppModule {}