import { DataSource, DataSourceOptions } from 'typeorm';
import { config } from 'dotenv';
import { User } from '../src/users/entities/user.entity';
import { Session } from '../src/users/entities/session.entity';

config({ path: '.env' });

// Data source options
export const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  url: process.env.DATABASE_URL,
  entities: [User, Session],
  migrations: ['dist/db/migrations/*.js'],
  synchronize: true, // only for development
};

const dataSource = new DataSource(dataSourceOptions);
export default dataSource;
