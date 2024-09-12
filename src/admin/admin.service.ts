import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import * as speakeasy from 'speakeasy';
import {
  sendEmail,
  ApiResponse,
  generateToken,
  setTokenCookie,
} from 'src/helper/common.helper';
import { Response, Request } from 'express'; 
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/entities/user.entity';
import { MoreThanOrEqual, Repository } from 'typeorm';

@Injectable()
export class AdminService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
  ) {}

  setTokenCookie(res: Response, token: string) {
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
    });
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 12);
  }

  async createAdmin() {
    try {
      const adminExists = await this.userRepository.findOne({
        where: { email: 'admin@example.com' },
      });
      
      const hashedPassword = await this.hashPassword('adminpassword');
      const newAdmin = this.userRepository.create({
       
          userName: 'Admin',
          email: 'admin@yahoo.com',
          position: 'Administrator',
          department: 'System',
          role: 'superadmin',
          password: hashedPassword,
          status: 'active',
          deviceTypes: [{ web: '', iOS: '', android: '' }],
       
      });
      await this.userRepository.save(newAdmin);
    } catch (error) {
      console.error('Error creating admin:', error);
      throw new HttpException(
        'Internal Server Error',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async findAdminByEmail(email: string) {
    return this.userRepository.findOne({ where: { email } });
  }

  async updateUserProfile(userId: string, data: any) {
    return this.userRepository.update({ id: userId }, data);
  }

  async sendOTPEmail(user: any, otp: any) {
    await sendEmail({
      email: user.email,
      subject: 'Your OTP Code',
      message: `Your OTP code is: ${otp}`,
    });
  }

  async enableMFA(email: string) {
    const admin = await this.findAdminByEmail(email);

    if (!admin) {
      throw new HttpException('Admin not found', HttpStatus.NOT_FOUND);
    }

    const secret = speakeasy.generateSecret({ name: 'YourAppName' });
    await this.userRepository.update({ email }, {
      mfaSecret: secret.base32,
      mfaEnabled: true,
    });

    return new ApiResponse(
      200,
      { secret: secret.otpauth_url },
      'MFA enabled successfully',
    );
  }

  async disableMFA(email: string) {
    const admin = await this.findAdminByEmail(email);

    if (!admin) {
      throw new HttpException('Admin not found', HttpStatus.NOT_FOUND);
    }

    await this.userRepository.update({ email }, {
      mfaEnabled: false,
      mfaSecret: null,
    });

    return new ApiResponse(200, {}, 'MFA disabled successfully');
  }

  async updateAdminProfile(adminId: string, data: any) {
   

    if (data.password) {
      data.password = await this.hashPassword(data.password);
    }

    await this.userRepository.update({ id: adminId }, data);

    return new ApiResponse(200, null, 'Profile updated successfully');
  }

  async recoverAdminAccount(email: string) {
    const admin = await this.findAdminByEmail(email);

    if (!admin) {
      throw new HttpException('Admin not found', HttpStatus.NOT_FOUND);
    }

    const recoveryToken = crypto.randomBytes(32).toString('hex');
    await this.updateUserProfile(admin.id, {
      resetPasswordToken: recoveryToken,
    });

    const recoveryUrl = `${process.env.FRONTEND_URL}/reset-password?token=${recoveryToken}`;
    await sendEmail({
      email: admin.email,
      subject: 'Admin Account Recovery',
      message: `Click the following link to reset your password: ${recoveryUrl}`,
    });

    return new ApiResponse(200, null, 'Recovery email sent');
  }

  async resetAdminPassword(
    token: string,
    newPassword: string,
    confirmPassword: string,
  ) {

    if(!token){
      throw new HttpException("token is required", HttpStatus.BAD_REQUEST)
    }

    if (newPassword !== confirmPassword) {
      throw new HttpException('Passwords do not match', HttpStatus.BAD_REQUEST);
    }

    const admin = await this.userRepository.findOne({
      where: { resetPasswordToken: token },
    });

    if (!admin) {
      throw new HttpException('Invalid token', HttpStatus.BAD_REQUEST);
    }

    const hashedPassword = await this.hashPassword(newPassword);
    await this.updateUserProfile(admin.id, {
      password: hashedPassword,
      resetPasswordToken: null,
    });

    return new ApiResponse(200, null, 'Password reset successfully');
  }

  async adminLogin(
    email: string,
    password: string,
    res: Response,
    req: Request,
    deviceInfo: { web?: string; iOS?: string; android?: string },
    otp?: string,
  ) {
    if (!email || !password) {
      throw new HttpException('Email or password is required', HttpStatus.UNAUTHORIZED);
    }
  
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
    }
  
    const deviceTypes = Array.isArray(user.deviceTypes) ? user.deviceTypes : [];
    const isRecognizedDevice = deviceTypes.some((device: any) =>
      (device.web && device.web === deviceInfo.web) ||
      (device.iOS && device.iOS === deviceInfo.iOS) ||
      (device.android && device.android === deviceInfo.android)
    );
  
    // If the device is recognized, proceed with OTP or login
    if (isRecognizedDevice) {
      if (!(await bcrypt.compare(password, user.password))) {
        throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
      }
  
      // Handle MFA if enabled
      if (user.mfaEnabled) {
        if (!otp) {
          const generatedOtp = speakeasy.totp({
            secret: user.mfaSecret,
            encoding: 'base32',
            step: 300,
          });
          const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // OTP expires in 5 minutes
  
          await this.updateUserProfile(user.id, {
            otpCode: generatedOtp,
            otpExpiry,
            otpSentAt: new Date(),
          });
          await this.sendOTPEmail(user, generatedOtp);
  
          throw new HttpException('OTP sent to your email', HttpStatus.UNAUTHORIZED);
        }
  
        const isOtpValid = speakeasy.totp.verify({
          secret: user.mfaSecret,
          encoding: 'base32',
          token: otp,
          window: 2,
          step: 300,
        });
  
        if (!isOtpValid || new Date() > new Date(user.otpExpiry)) {
          throw new HttpException('Invalid OTP or expired OTP', HttpStatus.UNAUTHORIZED);
        }
      }
  
      const token = this.jwtService.sign({
        userId: user.id,
        userName: user.userName,
        role: user.role,
      });
  
      res.cookie('accessToken', token, { httpOnly: true, secure: false });
      return new ApiResponse(200, { token }, 'Login successful');
    }
  
    // Handle unrecognized device login attempt
    const loginAttemptToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 10 * 60 * 1000); // Token expires in 10 minutes
  
    await this.updateUserProfile(user.id, {
      loginAttempt: loginAttemptToken,
      tokenExpiry,
      unrecognizedBrowser: deviceInfo.web || deviceInfo.iOS || deviceInfo.android,
    });
  
    const confirmUrl = `${process.env.FRONTEND_URL}/confirm-login?token=${loginAttemptToken}`;
    await sendEmail({
      email: user.email,
      subject: 'Confirm Login Attempt',
      message: `A login attempt was made from an unrecognized device. If this was you, please confirm by clicking the following link: ${confirmUrl}`,
    });
  
    throw new HttpException('Login from unrecognized device. Please confirm via email.', HttpStatus.UNAUTHORIZED);
  }
  
  

  async confirmAdminLogin(token: string, res: Response) {
    const user = await this.userRepository.findOne({
      where: { 
        loginAttempt: token,
        tokenExpiry: MoreThanOrEqual(new Date()),
      },
    });
  
    if (!user) {
      throw new HttpException('Invalid or expired confirmation token', HttpStatus.BAD_REQUEST);
    }
  
    const deviceInfo = Array.isArray(user.deviceTypes) ? user.deviceTypes : [];
    const deviceTypes = [
      ...deviceInfo,
      { web: user.unrecognizedBrowser },  // Store the new recognized device info
    ];
  
    await this.updateUserProfile(user.id, {
      loginAttempt: null,
      tokenExpiry: null,
      unrecognizedBrowser: null,
      deviceTypes,  // Update the deviceTypes
    });
  
    const jwtToken = generateToken(user.id, user.userName, user.role);
    res.cookie('accessToken', jwtToken, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });
    
    return new ApiResponse(200, { token: jwtToken }, 'Login confirmed and successful');
  }
  

  async sendOTP(email: string) {
    const admin = await this.findAdminByEmail(email);

    if (!admin || !admin.mfaEnabled) {
      throw new HttpException(
        'Admin not found or MFA not enabled',
        HttpStatus.BAD_REQUEST,
      );
    }

    const lastOtpSentTime = admin.otpSentAt || new Date(0);
    const timeSinceLastOtp =
      (new Date().getTime() - lastOtpSentTime.getTime()) / 1000;

    if (timeSinceLastOtp < 30) {
      throw new HttpException(
        'Please wait 30 seconds before requesting another OTP.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const otp = speakeasy.totp({
      secret: admin.mfaSecret,
      encoding: 'base32',
      step: 300,
    });
    const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // OTP expires in 5 minutes

    await this.updateUserProfile(admin.id, {
      otpCode: otp,
      otpExpiry,
      otpSentAt: new Date(),
    });

    await this.sendOTPEmail(admin, otp);

    return new ApiResponse(200, null, 'OTP sent successfully');
  }
}
