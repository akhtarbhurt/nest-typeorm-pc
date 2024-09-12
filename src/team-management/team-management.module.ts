import { Module } from '@nestjs/common';
import { TeamManagementController } from './team-management.controller';
import { TeamManagementService } from './team-management.service';
import { JwtModule } from '@nestjs/jwt';
import { TeamManagement } from 'src/entities/team-management.entity';
import { User } from 'src/entities/user.entity';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.ACCESS_TOKEN_SECRET, 
      signOptions: { expiresIn: '1d' },
    }),
    TypeOrmModule.forFeature([User, TeamManagement ])
  ],
  providers: [TeamManagementService, ],
  exports: [TeamManagementService],
  controllers: [TeamManagementController]
})
export class TeamManagementModule {}
