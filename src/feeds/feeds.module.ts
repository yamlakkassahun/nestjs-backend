import { Module } from '@nestjs/common';
import { FeedsService } from './feeds.service';
import { FeedsController } from './feeds.controller';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from 'src/auth/guards/jwt.strategy';
import { JwtGuard } from 'src/auth/guards/jwt.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';

@Module({
  imports: [
    JwtModule.registerAsync({
      useFactory: () => ({
        secret: process.env.JWT_SECRET,
        signOptions: { expiresIn: '3600s' },
      }),
    }),
  ],
  controllers: [FeedsController],
  providers: [FeedsService, JwtStrategy, JwtGuard, RolesGuard],
})
export class FeedsModule {}
