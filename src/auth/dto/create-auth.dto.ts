import { IsEmail, IsString, MaxLength, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Role } from '../entities/role.enum';

export class CreateAuthDto {
  @IsEmail()
  @ApiProperty({ type: String, description: 'email' }) // this will give the schema to the swagger api
  email: string;

  @IsString()
  @ApiProperty({ type: String, description: 'address' }) // this will give the schema to the swagger api
  address: string;

  @IsString()
  @ApiProperty({ description: 'role' }) // this will give the schema to the swagger api
  role: Role;

  @IsString()
  @ApiProperty({ type: String, description: 'firstName' }) // this will give the schema to the swagger api
  firstName: string;

  @IsString()
  @ApiProperty({ type: String, description: 'lastName' }) // this will give the schema to the swagger api
  lastName: string;

  @IsString()
  @ApiProperty({ type: String, description: 'phone' }) // this will give the schema to the swagger api
  phone: string;

  @IsString()
  @MinLength(8)
  @MaxLength(32)
  @ApiProperty({ type: String, description: 'Password' }) // this will give the schema to the swagger api
  password: string;
}
