export const moduleTemplate = `import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { {{EntityName}} } from './entities/{{entityFileName}}.entity';
import { {{EntityName}}Service } from './services/{{kebabCaseName}}.service';
import { {{EntityName}}Controller } from './controllers/{{kebabCaseName}}.controller';

@Module({
  imports: [TypeOrmModule.forFeature([{{EntityName}}])],
  providers: [{{EntityName}}Service],
  controllers: [{{EntityName}}Controller],
  exports: [{{EntityName}}Service],
})
export class {{EntityName}}Module {}
`;
