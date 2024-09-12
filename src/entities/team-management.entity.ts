import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToMany,
  CreateDateColumn,
  JoinTable,
} from 'typeorm';
import { User } from './user.entity';

@Entity()
export class TeamManagement {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  teamName: string;

  @Column()
  teamDescription: string;

  @Column()
  region: string;

  @ManyToMany(() => User, (user) => user.teamManagements)
  @JoinTable() // This is important for the members relationship
  members: User[];

  @Column()
  visualRepresentation: string;

  @Column()
  teamLeader: string;

  @Column()
  reportingLines: string;

  @Column('simple-json')
  teamPerformance: object[];

  @Column('simple-json')
  teamActivityLogs: object[];

  @ManyToMany(() => User, (user) => user.teamManagement)
  @JoinTable()
  subteam: User[] 

  @Column()
  status: string;

  @CreateDateColumn()
  createdAt: Date;
}
