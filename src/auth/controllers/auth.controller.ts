import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Request,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { FileInterceptor } from '@nestjs/platform-express';
import { join } from 'path';
import { map, Observable, of } from 'rxjs';
import { GetUser } from '../decorators/get.user.decorator';
import { Roles } from '../decorators/roles.decorator';
import { Auth } from '../entities/auth.entity';
import { Role } from '../entities/role.enum';
import { JwtGuard } from '../guards/jwt.guard';
import { RolesGuard } from '../guards/roles.guard';
import { isFileExtensionSafe, removeFile } from '../helpers/image-storage';
import { AuthService } from '../services/auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() user: Auth): Observable<Auth> {
    console.log(user);
    return this.authService.registerAccount(user);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(@Body() user: Auth): Observable<{ token: string }> {
    return this.authService
      .login(user)
      .pipe(map((jwt: string) => ({ token: jwt })));
  }

  @UseGuards(JwtGuard, RolesGuard)
  @Roles(Role.USER, Role.ADMIN)
  // @UseGuards(JwtGuard)
  @Get('user')
  getAdmin(@GetUser() user: Auth) {
    console.log(user);
    return 'user';
  }
}
