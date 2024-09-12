import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    CreateDateColumn,
    Index,
  } from 'typeorm';
  
  @Entity()
  export class Permissions {
    @PrimaryGeneratedColumn('uuid')
    id: string;
  
    @Column()
    permission: string;
  
    @CreateDateColumn()
    created_at: Date;
  
    
  }
  