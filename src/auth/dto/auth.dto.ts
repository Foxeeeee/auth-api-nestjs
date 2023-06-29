import { Type } from "class-transformer";
import { IsEmail, IsInt, IsNotEmpty, Length } from "class-validator";

export class AuthUserDto{
    
    @IsNotEmpty()
    @IsEmail()
    email: string;

    @IsNotEmpty()
    @Length(5,18, { message : 'Password must be at least 5 characters'})
    password: string;
}