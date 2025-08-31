import {
  Column,
  Entity,
  PrimaryGeneratedColumn,
  ManyToOne,
  CreateDateColumn,
} from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { IsDefined, IsNotEmpty } from 'class-validator';

@Entity({ name: 'sessions' })
export class Session {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  token: string;

  @ManyToOne(() => User, (user) => user.sessions)
  user: User;

  @Column({ default: false })
  revoked: boolean;

  @Column({ nullable: true })
  device: string;

  @IsDefined()
  @IsNotEmpty()
  @Column({ type: 'timestamp' })
  expires: Date;

  @CreateDateColumn()
  createdAt: Date;
}
