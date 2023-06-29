import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthUserDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt/dist';
import { jwtSecret } from 'utils/constant';
import { Request, Response} from 'express';
import { randomUUID } from 'crypto';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService){}

    async signup(dto: AuthUserDto){
        const {email, password} = dto;

        const foundUser = await this.prisma.user.findUnique({
            where: {email: email}
        })

        if (foundUser) {
            throw new BadRequestException('Email already exists')
        }

        const hashedPassword = await this.hashPassword(password);

        await this.prisma.user.create({
            data: {
                email,
                hashedPassword
            }
        })
        return { message : 'Sign Up was successful'};
    }

    async signin(dto: AuthUserDto, req: Request, res: Response){
        const {email, password} = dto;

        const userMatch = await this.prisma.user.findUnique({
            where: {
                email: email,
            }
        });

        if (!userMatch) {
            throw new BadRequestException('Wrong credentials');
        }

        const isMatch = await this.comparePassword({password, hash: userMatch.hashedPassword,});

        if (!isMatch) {
            throw new BadRequestException('Wrong credentials')
        }

        const token = await this.signToken({id: userMatch.id, email: userMatch.email})
        const refreshToken = await this.generateRefreshToken();

        if (!token || !refreshToken) {
            throw new ForbiddenException();
        }

        res.cookie('token', token);
        res.cookie('refreshToken', refreshToken);

        return res.send({ message : 'Login successful'});
    }

    async signout(req: Request, res: Response){
        res.clearCookie('token');
        res.clearCookie('refreshToken');
        return res.send({ message: 'Logout successful'})
    }

    async hashPassword(password: string) {
        const saltOrRounds = 10;

        return await bcrypt.hash(password, saltOrRounds);
        
    }

    async comparePassword(args: {password: string, hash: string}) {
        return await bcrypt.compare(args.password, args.hash);
    }

    async signToken(args: {id: String, email: string}){
        const payload = args

        return this.jwt.signAsync(payload, {secret: jwtSecret})
    }

    generateRefreshToken(): string {
        const refreshToken = randomUUID();
        return refreshToken;
    }
}
