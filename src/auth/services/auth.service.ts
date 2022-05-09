import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Auth, AuthDocument } from '../entities/auth.entity';
import * as bcrypt from 'bcrypt';
import { from, Observable, of } from 'rxjs';
import { catchError, map, switchMap, tap } from 'rxjs/operators';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(Auth.name) private userModel: Model<AuthDocument>,
    private jwtService: JwtService,
  ) {}

  hashPassword(password: string): Observable<string> {
    return from(bcrypt.hash(password, 12));
  }

  doesUserExist(email: string): Observable<boolean> {
    return from(this.userModel.findOne({ email })).pipe(
      switchMap((user: Auth) => {
        return of(!!user);
      }),
    );
  }

  registerAccount(user: Auth): Observable<Auth> {
    const { email, password, address, firstName, lastName, phone } = user;

    return this.doesUserExist(email).pipe(
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
}
