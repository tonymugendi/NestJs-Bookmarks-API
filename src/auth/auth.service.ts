import { ForbiddenException, Injectable } from '@nestjs/common';
import * as argon from 'argon2';

import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    try {
      // Generate the password hash
      const hashedPassword = await argon.hash(dto.password);
      // Save the new user in the db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hashedPassword,
        },
      });

      delete user.hashedPassword;
      // return the saved user
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }

      throw error;
    }
  }
  async signin(dto: AuthDto) {
    // Find user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    // If user does not exist, throw exception
    if (!user) throw new ForbiddenException('Credentials Incorrect');
    // Compare password
    const pwMathces = await argon.verify(user.hashedPassword, dto.password);
    // If password is incorrrect, throw exception
    if (!pwMathces) {
      throw new ForbiddenException('Credentials Incorrect');
    }
    // Send back the user
    delete user.hashedPassword;
    return user;
  }
}
