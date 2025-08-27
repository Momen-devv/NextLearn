import {
  Column,
  Entity,
  PrimaryGeneratedColumn,
  ManyToOne,
  CreateDateColumn,
} from 'typeorm';
import { User } from './user.entity';

@Entity({ name: 'refreshTokens' })
export class RefreshToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  token: string;

  @ManyToOne(() => User, (user) => user.refreshTokens)
  user: User;

  @Column({ default: false })
  revoked: boolean;

  @Column({ nullable: true })
  device: string;

  @Column()
  expires: Date;

  @CreateDateColumn()
  createdAt: Date;
}
