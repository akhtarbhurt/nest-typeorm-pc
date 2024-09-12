import { Injectable, HttpException, HttpStatus, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import { TeamManagement } from 'src/entities/team-management.entity';
import { CreateTeamDto, UpdateTeamDto, SearchAndFilterTeamsDto } from './dto/team-management.dto';
import * as jwt from 'jsonwebtoken';
import { User } from 'src/entities/user.entity';

@Injectable()
export class TeamManagementService {
  constructor(
    @InjectRepository(TeamManagement)
    private readonly teamManagementRepository: Repository<TeamManagement>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>
  ) {}

  async validateMembers(members: string[]) {
    return await this.userRepository.find({
      where: { id: In(members) },
      select: ['id']
    });
  }

  validateTeamPerformance(teamPerformance: any[]) {
    if (teamPerformance) {
      const isValid = teamPerformance.every(performance =>
        typeof performance.metric === 'string' && typeof performance.value === 'number'
      );

      if (!isValid) {
        throw new HttpException('Invalid team performance structure.', HttpStatus.BAD_REQUEST);
      }
    }
  }

  validateTeamActivityLogs(teamActivityLogs: any[]) {
    if (teamActivityLogs) {
      const isValid = teamActivityLogs.every(log =>
        typeof log.date === 'string' && typeof log.activity === 'string'
      );

      if (!isValid) {
        throw new HttpException('Invalid team activity logs structure.', HttpStatus.BAD_REQUEST);
      }
    }
  }

  verifyToken(token: string) {
    return jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
  }
  

  async createTeam(createTeamDto: CreateTeamDto, teamLeader: string) {
    const members = await this.userRepository.findByIds(createTeamDto.members);  // Fetch members by userId
  
    if (!members || members.length === 0) {
      throw new HttpException('No valid members provided.', HttpStatus.BAD_REQUEST);
    }
    const user = await this.userRepository.find();
  const filterUser = user.filter(elem => elem.role === "manager");
    const teamData: Partial<TeamManagement> = {
      teamLeader,
      visualRepresentation: createTeamDto.visualRepresentation || 'default value',
      members,  
      subteam: filterUser,  
      status: 'active',
      teamName: createTeamDto.teamName,
      region: createTeamDto.region,
      reportingLines: createTeamDto.reportingLines,
      teamPerformance: createTeamDto.teamPerformance,
      teamActivityLogs: createTeamDto.teamActivityLogs,
    };
  
    if (createTeamDto.teamDescription) {
      teamData.teamDescription = createTeamDto.teamDescription;
    }
  
    const newTeam = await this.teamManagementRepository.save(teamData);
    return newTeam;
  }
  
  async getAllTeams() {
    const teams = await this.teamManagementRepository.find({
      relations: ['members'],  // Fetch members relation
    });
  
    return teams.map(team => ({
      id: team.id,
      teamName: team.teamName,
      teamDescription: team.teamDescription,
      region: team.region,
      members: team.members.map(member => ({
        id: member.id,           
        userName: member.userName,  
        email: member.email,     
        position: member.position,  
        department: member.department,  
        role: member.role,       
      })),
      status: team.status,
      createdAt: team.createdAt,
    }));
  }
  
  
  

  async findTeamById(teamId: string) {
    return await this.teamManagementRepository.findOne({
      where: { id: teamId },
    });
  }

  async updateTeam(updateTeamDto: UpdateTeamDto) {
    const { teamId, members } = updateTeamDto;

    const membersToAdd = members?.add || [];
    const membersToRemove = members?.remove || [];

    const team = await this.teamManagementRepository.findOne({ where: { id: teamId }, relations: ['members'] });

    if (team) {
      team.members = [
        ...team.members.filter(member => !membersToRemove.includes(member.id)),
        ...membersToAdd.map(id => ({ id } as User))
      ];
      await this.teamManagementRepository.save(team);
    }
  }

  async searchTeamById(id: string) {
    return await this.teamManagementRepository.findOne({
      where: { id },
    });
  }

  async organizeTeamsByRegion(regionName: string) {
    return await this.teamManagementRepository.find({
      where: { region: regionName },
    });
  }

  async searchAndFilterTeams(dto: SearchAndFilterTeamsDto) {
    const { teamName, region, memberId, limit = 10, offset = 0 } = dto;
  
    const queryBuilder = this.teamManagementRepository.createQueryBuilder('team');
  
    if (teamName) {
      queryBuilder.andWhere('team.teamName ILIKE :teamName', { teamName: `%${teamName}%` });
    }
  
    if (region) {
      queryBuilder.andWhere('team.region ILIKE :region', { region: `%${region}%` });
    }
  
    if (memberId) {
      queryBuilder
        .leftJoin('team.members', 'members')  // Correctly join members
        .andWhere('members.id = :memberId', { memberId });  // Filter based on memberId
    }
  
    queryBuilder
      .leftJoinAndSelect('team.members', 'members')  // Fetch the members relationship
      .skip(offset)
      .take(limit);
  
    const [teams, totalCount] = await queryBuilder.getManyAndCount();
  
    const pagination = {
      limit,
      offset,
      totalCount,
    };
  
    return { teams, pagination };
  }
  

  async getTeamPerformanceAndActivityLogs(id: string) {
    return await this.teamManagementRepository.findOne({
      where: { id },
      select: ['teamPerformance', 'teamActivityLogs'],
    });
  }

  async getTeamHierarchy(teamId: string) {
    return await this.teamManagementRepository.findOne({
      where: { id: teamId },
      relations: ['subteam', 'members'],
    });
  }
}
