import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { UserManagementModule } from './user-management/user-management.module';
import { JwtModule } from '@nestjs/jwt';
import { AdminModule } from './admin/admin.module';
import { TeamManagementModule } from './team-management/team-management.module';
import { APP_GUARD } from '@nestjs/core';
import { RolesGuard } from './middleware/roleGuard.middleware';
import { RolesController } from './roles/roles.controller';
import { RolesService } from './roles/roles.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Role } from './entities/role.entity';
import { TeamManagement } from './entities/team-management.entity';
import { Permissions } from './entities/permission.entity';
import { RolesModule } from './roles/roles.module';

@Module({
  imports: [
    UserManagementModule,
    AdminModule,
    TeamManagementModule,
   
    RolesModule,
    ConfigModule.forRoot({ isGlobal: true }),
    JwtModule.register({
      secret: process.env.ACCESS_TOKEN_SECRET,
      signOptions: { expiresIn: '1d' },
    }),
   
    TypeOrmModule.forRoot({
      type: "postgres",
      host: "localhost",
      port: 5432,
      username: "postgres",
      password: "akhtar123",
      database: "pcDB",
      entities: [User, Role, TeamManagement, Permissions],
      synchronize: true
    })
  ],
  controllers: [AppController, RolesController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
    
  ],
})
export class AppModule {}
