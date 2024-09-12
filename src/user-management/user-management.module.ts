import { Module } from '@nestjs/common';
import { UserManagementController } from './user-management.controller';
import { UserManagementService } from './user-management.service';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/entities/user.entity';
import { Role } from 'src/entities/role.entity';
 

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.ACCESS_TOKEN_SECRET, 
      signOptions: { expiresIn: '1d' },
    }),
    TypeOrmModule.forFeature([User, Role])
  ],
  providers: [UserManagementService],
  exports: [UserManagementService],
  controllers: [UserManagementController]
})
export class UserManagementModule {}
