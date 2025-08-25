import { Column, Entity, PrimaryGeneratedColumn, ManyToOne } from 'typeorm';
import { User } from './user.entity';

@Entity({ name: 'refreshTokens' })
export class RefreshToken {
  @PrimaryGeneratedColumn('uuid')
  id: number;

  @Column({ unique: true })
  token: string;

  @Column()
  userId: string;

  @ManyToOne(() => User, (user) => user.refreshTokens)
  user: User;

  @Column()
  expires: Date;

  @Column({ default: false })
  revoked: boolean;

  @Column({ nullable: true })
  device: string;
}
