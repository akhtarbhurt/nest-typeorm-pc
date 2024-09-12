import { Module } from '@nestjs/common';
import { AdminController } from './admin.controller';
import { AdminService } from './admin.service';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/entities/user.entity';

@Module({
  controllers: [AdminController],
  providers: [AdminService],
  imports: [ JwtModule.register({
    secret: process.env.ACCESS_TOKEN_SECRET, 
    signOptions: { expiresIn: '1d' },
  }),
  TypeOrmModule.forFeature([User])
]
})
export class AdminModule {}
