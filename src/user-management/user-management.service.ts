import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, MoreThan } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { sendEmail } from 'src/helper/common.helper';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { RequestPasswordResetDto } from './dto/request-password-reset.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { User } from 'src/entities/user.entity';
import { Role } from 'src/entities/role.entity';

@Injectable()
export class UserManagementService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Role)
    private readonly roleRepository: Repository<Role>,
    private readonly jwtService: JwtService,
  ) {}

  async hashPassword(password: string): Promise<string> {
    return await bcrypt.hash(password, 10);
  }

  async createUser(createUserDto: CreateUserDto) {
    const { email, password } = createUserDto;

    const existingUser = await this.userRepository.findOne({ where: { email } });
    if (existingUser) {
      throw new HttpException('Email already exists, please try another email', HttpStatus.CONFLICT);
    }

    const hashedPassword = await this.hashPassword(password);

    const user = this.userRepository.create({
      ...createUserDto,
      password: hashedPassword,
    });
    await this.userRepository.save(user);

    return { userId: user.id, message: 'User created successfully' };
  }

  async fetchAllUser() {
    const users = await this.userRepository.find({
      relations: ['roles'],
    });

    return users.map((user) => ({
      id: user.id,
      userName: user.userName,
      email: user.email,
      position: user.position,
      department: user.department,
      role: user.role,
      status: user.status,
      roles: user.roles.map((role) => ({
        roleName: role.roleName,
        assignPermissions: role.assignPermissions,
      })),
    }));
  }

  async loginUser(loginUserDto: LoginUserDto, res: any) {
    const { email, password } = loginUserDto;

    const user = await this.userRepository.findOne({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new HttpException('Invalid email or password', HttpStatus.UNAUTHORIZED);
    }

    if (user.role === 'superadmin') {
      throw new HttpException('Admin cannot login from user route', HttpStatus.UNAUTHORIZED);
    }

    const token = this.jwtService.sign({
      userId: user.id,
      userName: user.userName,
      role: user.role,
    });
    res.cookie('accessToken', token, { httpOnly: true, secure: false });

    return { token, message: 'Login successful' };
  }

  async updateUser(updateUserDto: UpdateUserDto, userId: string) {
    const { email } = updateUserDto;

    // Check if email is provided before querying for an existing user
    if (email) {
      const existingUser = await this.userRepository.findOne({ where: { email } });

      // If an existing user with the same email is found, but it doesn't match the current user, throw an error
      if (existingUser && existingUser.id !== userId) {
        throw new HttpException('Email is already in use by another account', HttpStatus.CONFLICT);
      }
    }

    // Update the user with the provided data
    await this.userRepository.update(userId, updateUserDto);

    return { message: 'User updated successfully' };
  }

  async deactivateUser(userId: string) {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    await this.userRepository.update(userId, { status: 'inactive' });

    return { message: 'User deactivated successfully' };
  }

  async getUserById(userId: string) {
    const user = await this.userRepository.findOneOrFail({
      where: { id: userId },
      relations: ['roles'],
    });

    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    return {
      userName: user.userName,
      email: user.email,
      position: user.position,
      department: user.department,
      role: user.role,
      status: user.status,
      roles: user.roles.map((role) => ({
        roleName: role.roleName,
        assignPermissions: role.assignPermissions,
      })),
    };
  }

  async logoutUser(res: any) {
    res.clearCookie('accessToken', { httpOnly: true, secure: false });
    return { message: 'Logout successful' };
  }

  async requestPasswordReset(requestPasswordResetDto: RequestPasswordResetDto) {
    const { email } = requestPasswordResetDto;

    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new HttpException('User with this email does not exist', HttpStatus.NOT_FOUND);
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    const resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hour

    await this.userRepository.update(user.id, {
      resetPasswordToken,
      resetPasswordExpires,
    });

    const message = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

    try {
      await sendEmail({
        email: user.email,
        subject: 'Password Reset',
        message: `You requested a password reset. Please go to this link to reset your password: ${message}`,
      });

      return { message: 'Email sent' };
    } catch (error) {
      throw new HttpException('Email could not be sent', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const { token, newPassword, confirmPassword } = resetPasswordDto;

    if (newPassword !== confirmPassword) {
      throw new HttpException('Passwords do not match', HttpStatus.BAD_REQUEST);
    }

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await this.userRepository.findOne({
      where: {
        resetPasswordToken: hashedToken,
        resetPasswordExpires: MoreThan(new Date()),
      },
    });

    if (!user) {
      throw new HttpException('Token is invalid or has expired', HttpStatus.BAD_REQUEST);
    }

    const hashedPassword = await this.hashPassword(newPassword);

    await this.userRepository.update(user.id, {
      password: hashedPassword,
      resetPasswordToken: null,
      resetPasswordExpires: null,
    });

    return { message: 'Password reset successfully' };
  }
}
