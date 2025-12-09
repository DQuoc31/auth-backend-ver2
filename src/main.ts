import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  // Bật CORS cho frontend React
  app.enableCors({
    //origin: configService.get('FRONTEND_URL') || 'http://localhost:3000',
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  });

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Loại bỏ fields không có trong DTO
      forbidNonWhitelisted: true, // Báo lỗi nếu có fields thừa
      transform: true, // Tự động transform types
    }),
  );

  const port = configService.get('PORT') || 3001;

  // Thêm tham số '0.0.0.0' để lắng nghe mọi IP
  await app.listen(port, '0.0.0.0');
  console.log(`Ứng dụng đang chạy trên cổng ${port}`);
}
bootstrap();