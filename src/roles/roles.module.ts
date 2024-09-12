import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { Permissions } from "src/entities/permission.entity";
import { Role } from "src/entities/role.entity";
import { User } from "src/entities/user.entity";
import { RolesService } from "./roles.service";
import { RolesController } from "./roles.controller";


@Module({
    imports:[TypeOrmModule.forFeature([User, Role, Permissions])],
    providers: [RolesService],
    exports: [RolesService],
    controllers: [RolesController]
})
export class RolesModule {}
