import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { CreateRoleDto } from './dto/CreateRoleDto';
import { UpdatePermissionsDto } from './dto/UpdatePermissionsDto';
import { Role } from 'src/entities/role.entity';
import { User } from 'src/entities/user.entity';
import { Permissions } from 'src/entities/permission.entity';

@Injectable()
export class RolesService {
  constructor(
    @InjectRepository(Role)
    private readonly roleRepository: Repository<Role>,
    @InjectRepository(Permissions)
    private readonly permissionRepository: Repository<Permissions>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async createPermission(data: any) {
    const newPermission = this.permissionRepository.create(data);
    return await this.permissionRepository.save(newPermission);
  }

  async fetchPermissions() {
    return await this.permissionRepository.find();
  }

  async assignRole(dto: CreateRoleDto, user: any) {
    const existingRole = await this.roleRepository.findOne({ where: { user: { id: dto.userId } } });

    if (existingRole) {
      throw new BadRequestException('User already has an assigned role.');
    }

    const userExists = await this.userRepository.findOne({where:{ id : dto.userId}});
    if (!userExists) {
      throw new NotFoundException('User not found');
    }
    
    const newRole = this.roleRepository.create({
      roleName: dto.roleName,
      assignPermissions: dto.assignPermissions,
      user: userExists,
      status: dto.status,
    });

    return await this.roleRepository.save(newRole);
  }

  async createRole(roleName: string): Promise<{ roleName: string }> {
    const newRole = this.roleRepository.create({ roleName });
    const savedRole = await this.roleRepository.save(newRole);
  
   
    return { roleName: savedRole.roleName };
  }

  async fetchAllPermissions() {
    const roles = await this.roleRepository.find({
      select: ['roleName', 'id', 'status'],
    });

    if (!roles.length) {
      throw new NotFoundException('No roles found');
    }

    return roles;
  }

  async updatePermissions(dto: UpdatePermissionsDto, user: any) {
    // Fetch existing permissions to validate the incoming permissions
    const permissions = await this.permissionRepository.find();
    const validPermissions = permissions.map(p => p.permission);
    
    // Validate the permissions sent in the DTO
    const invalidPermissions = dto?.assignPermissions?.filter((p) => !validPermissions.includes(p));
  
    if (invalidPermissions?.length) {
      throw new Error(`Invalid permissions: ${invalidPermissions.join(', ')}`);
    }
  
    // Prepare update data, only include fields that are present in the DTO
    const updateData: Partial<Role> = {};
  
    if (dto.roleName) {
      updateData.roleName = dto.roleName;
    }
  
    if (dto.assignPermissions) {
      updateData.assignPermissions = dto.assignPermissions;
    }
  
    if (Object.keys(updateData).length === 0) {
      throw new BadRequestException('No valid data provided for update');
    }
  
    // Execute the update operation
    const result = await this.roleRepository.update(
      { user: { id: dto.userId } },
      updateData
    );
  
    if (result.affected === 0) {
      throw new NotFoundException('Role not found for the given userId');
    }
  
    return result;
  }
  

  async deactivatePermissions(userId: string) {
    const result = await this.roleRepository.update(
      { user: { id: userId } },
      { status: 'inactive' }
    );

    if (result.affected === 0) {
      throw new NotFoundException('Role not found for the given userId');
    }

    return result;
  }

  async searchPermissionByUserId(userId: string) {
    const userRoles = await this.roleRepository.find({
      where: { user: { id: userId } },
      select: ['assignPermissions'],
    });

    if (!userRoles.length) {
      throw new NotFoundException('No permissions found for the given userId');
    }

    return userRoles;
  }
}
