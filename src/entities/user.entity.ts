import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    ManyToOne,
    OneToMany,
    CreateDateColumn,
    Index,
  } from 'typeorm';
  import { Role } from './role.entity';
  import { TeamManagement } from './team-management.entity';
  
  @Entity()
  export class User {
    @PrimaryGeneratedColumn('uuid')
    id: string;
  
    @Column()
    userName: string;
  
    @Index({ unique: true })
    @Column()
    email: string;
  
    @Column()
    position: string;
  
    @Column()
    department: string;
  
    @Column()
    role: string;
  
    @Column()
    password: string;
  
    @Column({ default: 'active' })
    status: string;
  
    @Column({ nullable: true })
    resetPasswordToken: string;
  
    @Column({ type: 'timestamp', nullable: true })
    resetPasswordExpires: Date;
  
    @Column({ type: 'timestamp', nullable: true })
    tokenExpiry: Date;
  
    @OneToMany(() => Role, (role) => role.user)
    roles: Role[];
  
    @OneToMany(() => TeamManagement, (team) => team.members)
    teamManagements: TeamManagement[];
  
    @OneToMany(() => TeamManagement, (team) => team.subteam)
    teamManagement: TeamManagement[];
  
    @Column({ type: 'json', default: () => "'[]'" })
    deviceTypes: object[];
  
    @Column({ nullable: true })
    unrecognizedBrowser: string;
  
    @Column({ nullable: true })
    loginAttempt: string;
  
    @Column({ default: false })
    mfaEnabled: boolean;
  
    @Column({ nullable: true })
    mfaSecret: string;
  
    @Column({ nullable: true })
    otpCode: string;
  
    @Column({ type: 'timestamp', nullable: true })
    otpExpiry: Date;
  
    @CreateDateColumn()
    createdAt: Date;
  
    @Column({ type: 'timestamp', nullable: true })
    otpSentAt: Date;
  }
  