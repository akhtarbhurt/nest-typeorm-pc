import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    ManyToOne,
    CreateDateColumn,
    Index,
  } from 'typeorm';
  import { User } from './user.entity';
  
  @Entity()
  export class Role {
    @PrimaryGeneratedColumn('uuid')
    id: string;
  
    @Column()
    roleName: string;
  
    @Column('simple-array', { nullable: true, default: [] })
    assignPermissions: string[];
  
    @ManyToOne(() => User, (user) => user.roles, { onDelete: 'CASCADE' })
    user: User;
  
    @Index()
    @Column({nullable: true})
    userId: string;
  
    @CreateDateColumn()
    createdAt: Date;
  
    @Column({ default: 'active' })
    status: string;
  }
  