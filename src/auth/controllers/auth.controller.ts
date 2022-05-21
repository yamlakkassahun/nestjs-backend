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
import { ApiBearerAuth } from '@nestjs/swagger';
import { map, Observable } from 'rxjs';
import { GetUser } from '../decorators/get.user.decorator';
import { Roles } from '../decorators/roles.decorator';
import { CreateAuthDto } from '../dto/create-auth.dto';
import { UpdateAuthDto } from '../dto/update-auth.dto';
import { UpdatePasswordDto } from '../dto/update-password.dto';
import { Auth } from '../entities/auth.entity';
import { Role } from '../entities/role.enum';
import { JwtGuard } from '../guards/jwt.guard';
import { RolesGuard } from '../guards/roles.guard';
import { AuthService } from '../services/auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  registerAccount(@Body() user: CreateAuthDto): Promise<Observable<Auth>> {
    return this.authService.registerAccount(user);
  }

  @Post('signin')
  @HttpCode(HttpStatus.OK)
  login(@Body() user: Auth): Observable<{ token: string }> {
    return this.authService
      .login(user)
      .pipe(map((jwt: string) => ({ token: jwt })));
  }

  @UseGuards(JwtGuard, RolesGuard)
  @Roles(Role.USER, Role.ADMIN)
  @ApiBearerAuth()
  @Get('user')
  getAdmin(@GetUser() user) {
    return this.authService.findUserById(user._id);
  }

  @Get()
  @UseGuards(JwtGuard, RolesGuard)
  @Roles(Role.ADMIN)
  getAllUsers(): Observable<Auth[]> {
    return this.authService.findAllUsers();
  }

  @Get(':id')
  @UseGuards(JwtGuard, RolesGuard)
  @Roles(Role.ADMIN)
  getUserById(@Param('id') id: string): Observable<Auth> {
    return this.authService.findUserById(id);
  }

  @Post('register')
  @UseGuards(JwtGuard, RolesGuard)
  @Roles(Role.ADMIN)
  register(@Body() user: CreateAuthDto): Promise<Observable<Auth>> {
    return this.authService.registerUser(user);
  }

  @Put(':id/update')
  @UseGuards(JwtGuard, RolesGuard)
  @Roles(Role.ADMIN)
  update(
    @Param('id') id: string,
    @Body() user: UpdateAuthDto,
  ): Promise<Observable<Auth>> {
    return this.authService.updateUser(id, user);
  }

  @Delete(':id')
  @UseGuards(JwtGuard, RolesGuard)
  @Roles(Role.ADMIN)
  delete(@Param('id') id: string): Observable<Auth> {
    return this.authService.deleteUser(id);
  }

  //update/change password
  @Post('change-password')
  @UseGuards(JwtGuard)
  ChangePassword(
    @GetUser() user: any,
    @Body() updatePasswordDto: UpdatePasswordDto,
  ) {
    return this.authService.ChangePassword(user, updatePasswordDto);
  }
}
