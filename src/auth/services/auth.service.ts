import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Auth, AuthDocument } from '../entities/auth.entity';
import * as bcrypt from 'bcrypt';
import { from, Observable, of } from 'rxjs';
import { catchError, map, switchMap, tap } from 'rxjs/operators';
import { UpdateAuthDto } from '../dto/update-auth.dto';
import { Role } from '../entities/role.enum';
import { CreateAuthDto } from '../dto/create-auth.dto';
import { UpdatePasswordDto } from '../dto/update-password.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(Auth.name) private userModel: Model<AuthDocument>,
    private jwtService: JwtService,
  ) {}

  hashPassword(password: string): Observable<string> {
    return from(bcrypt.hash(password, 12));
  }

  async doesUserExist(email: string): Promise<Observable<boolean>> {
    return from(this.userModel.findOne({ email })).pipe(
      switchMap((user: Auth) => {
        return of(!!user);
      }),
    );
  }

  async registerAccount(user: CreateAuthDto): Promise<Observable<Auth>> {
    const { email, password, address, firstName, lastName, phone, role } = user;

    return (await this.doesUserExist(email)).pipe(
      tap((doesUserExist: boolean) => {
        if (doesUserExist)
          throw new HttpException(
            'A user has already been created with this email address',
            HttpStatus.BAD_REQUEST,
          );
      }),
      switchMap(() => {
        let userRole = Role.USER;
        if (role === 'admin') {
          userRole = Role.ADMIN;
        } else if (role === 'super') {
          userRole = Role.SUPER;
        }

        return this.hashPassword(password).pipe(
          switchMap((hashedPassword: string) => {
            return from(
              this.userModel.create({
                firstName,
                lastName,
                email,
                address,
                phone,
                role: userRole,
                password: hashedPassword,
              }),
            ).pipe(
              map((user: Auth) => {
                return user;
              }),
            );
          }),
        );
      }),
    );
  }

  validateUser(email: string, password: string): Observable<Auth> {
    return from(this.userModel.findOne({ email })).pipe(
      switchMap((user) => {
        if (!user) {
          throw new HttpException(
            { status: HttpStatus.FORBIDDEN, error: 'Invalid Credentials' },
            HttpStatus.FORBIDDEN,
          );
        }
        return from(bcrypt.compare(password, user.password)).pipe(
          map((isValidPassword: boolean) => {
            if (isValidPassword) {
              delete user.password;
              return user;
            }
            throw new HttpException(
              { status: HttpStatus.FORBIDDEN, error: 'Invalid Credentials' },
              HttpStatus.FORBIDDEN,
            );
          }),
        );
      }),
    );
  }

  login(user: Auth): Observable<string> {
    const { email, password } = user;
    return this.validateUser(email, password).pipe(
      switchMap((user: Auth) => {
        if (user) {
          // create JWT - credentials
          return from(this.jwtService.signAsync({ user }));
        }
      }),
    );
  }

  getJwtUser(jwt: string): Observable<Auth | null> {
    return from(this.jwtService.verifyAsync(jwt)).pipe(
      map(({ user }: { user: Auth }) => {
        return user;
      }),
      catchError(() => {
        return of(null);
      }),
    );
  }

  findAllUsers(): Observable<Auth[] | any> {
    return from(this.userModel.find());
  }

  findUserById(id: string): Observable<Auth> {
    return from(this.userModel.findById(id)).pipe(
      map((user) => {
        if (!user) {
          throw new HttpException(
            { status: HttpStatus.FORBIDDEN, error: 'User Was Not Found' },
            HttpStatus.FORBIDDEN,
          );
        }
        return user;
      }),
    );
  }

  async registerUser(user: Auth): Promise<Observable<Auth>> {
    const { email, password, address, firstName, lastName, phone } = user;

    return (await this.doesUserExist(email)).pipe(
      tap((doesUserExist: boolean) => {
        if (doesUserExist)
          throw new HttpException(
            'A user has already been created with this email address',
            HttpStatus.BAD_REQUEST,
          );
      }),
      switchMap(() => {
        return this.hashPassword(password).pipe(
          switchMap((hashedPassword: string) => {
            return from(
              this.userModel.create({
                firstName,
                lastName,
                email,
                address,
                phone,
                password: hashedPassword,
              }),
            ).pipe(
              map((user: Auth) => {
                return user;
              }),
            );
          }),
        );
      }),
    );
  }

  async updateUser(id: string, user: UpdateAuthDto): Promise<Observable<Auth>> {
    const { email, password, address, firstName, lastName, phone, role } = user;

    return this.hashPassword(password).pipe(
      switchMap((hashedPassword: string) => {
        return from(this.userModel.findById(id)).pipe(
          map((user) => {
            let userRole = Role.USER;
            if (role === 'admin') {
              userRole = Role.ADMIN;
            } else if (role === 'super') {
              userRole = Role.SUPER;
            }

            if (!user) {
              throw new HttpException(
                { status: HttpStatus.FORBIDDEN, error: 'User Was Not Found' },
                HttpStatus.FORBIDDEN,
              );
            }

            user.email = email;
            user.password = hashedPassword;
            user.address = address;
            user.firstName = firstName;
            user.lastName = lastName;
            user.role = userRole;
            user.phone = phone;
            user.save();
            return user;
          }),
        );
      }),
    );
  }
  //password update
  ChangePassword(user: any, updatePasswordDto: UpdatePasswordDto) {
    const { oldPassword, newPassword } = updatePasswordDto;
    return this.hashPassword(newPassword).pipe(
      switchMap((hashedPassword: string) => {
        return from(this.userModel.findById(user._id)).pipe(
          map((user) => {
            if (!user && bcrypt.compare(oldPassword, user.password)) {
              throw new HttpException(
                { status: HttpStatus.FORBIDDEN, error: 'User Was Not Found' },
                HttpStatus.FORBIDDEN,
              );
            }

            user.password = hashedPassword;
            user.save();
            return user;
          }),
        );
      }),
    );
  }

  deleteUser(id: string): Observable<Auth> {
    return from(this.userModel.findByIdAndDelete(id));
  }
}
