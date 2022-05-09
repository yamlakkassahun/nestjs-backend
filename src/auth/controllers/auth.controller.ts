import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
  Param,
  Put,
  Delete,
} from '@nestjs/common';
import { map, Observable } from 'rxjs';
import { GetUser } from '../decorators/get.user.decorator';
import { Roles } from '../decorators/roles.decorator';
import { CreateAuthDto } from '../dto/create-auth.dto';
import { UpdateAuthDto } from '../dto/update-auth.dto';
import { Auth } from '../entities/auth.entity';
import { Role } from '../entities/role.enum';
import { JwtGuard } from '../guards/jwt.guard';
import { RolesGuard } from '../guards/roles.guard';
import { AuthService } from '../services/auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register-account')
  registerAccount(@Body() user: Auth): Observable<Auth> {
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

  @Get()
  getAllUsers(): Observable<Auth[]> {
    return this.authService.findAllUsers();
  }

  @Get(':id')
  getUserById(@Param('id') id: string): Observable<Auth> {
    return this.authService.findUserById(id);
  }

  @Post('register')
  register(@Body() user: CreateAuthDto): Observable<Auth> {
    return this.authService.registerUser(user);
  }

  @UseGuards(JwtGuard)
  @Put(':id/update')
  update(
    @Param('id') id: string,
    @Body() user: UpdateAuthDto,
  ): Observable<Auth> {
    return this.authService.updateUser(id, user);
  }

  @UseGuards(JwtGuard)
  @Delete(':id')
  delete(@Param('id') id: string): Observable<Auth> {
    return this.authService.deleteUser(id);
  }
}
