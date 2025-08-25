import { DataSource, DataSourceOptions } from 'typeorm';
import { config } from 'dotenv';
import { User } from '../src/users/entities/user.entity';
import { RefreshToken } from '../src/users/entities/refresh-token.entity';

config({ path: '.env' });

// Data source options
export const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  url: process.env.DATABASE_URL,
  entities: [User, RefreshToken],
  migrations: ['dist/db/migrations/*.js'],
  synchronize: true, // only for development
};

const dataSource = new DataSource(dataSourceOptions);
export default dataSource;
