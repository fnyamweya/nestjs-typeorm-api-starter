export const serviceTemplate = `import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { FindManyOptions, Like, Repository } from 'typeorm';
import { {{EntityName}} } from '../entities/{{entityFileName}}.entity';
import { Create{{EntityName}}Dto } from '../dto/create-{{kebabCaseName}}.dto';
import { Filter{{EntityName}}Dto } from '../dto/filter-{{kebabCaseName}}.dto';
import { Update{{EntityName}}Dto } from '../dto/update-{{kebabCaseName}}.dto';

@Injectable()
export class {{EntityName}}Service {
  constructor(
    @InjectRepository({{EntityName}})
    private {{camelCaseName}}Repository: Repository<{{EntityName}}>,
  ) {}

  async create(create{{EntityName}}Dto: Create{{EntityName}}Dto) {
    // Check if {{entityName}} with same identifier already exists (customize this based on your entity)
    // const existing{{EntityName}} = await this.{{camelCaseName}}Repository.findOne({
    //   where: { /* add your unique field here */ },
    // });

    // if (existing{{EntityName}}) {
    //   throw new ConflictException(
    //     \`{{EntityName}} with this identifier already exists\`,
    //   );
    // }

    const {{camelCaseName}} = this.{{camelCaseName}}Repository.create(create{{EntityName}}Dto);
    return await this.{{camelCaseName}}Repository.save({{camelCaseName}});
  }

  async findAll(filter: Filter{{EntityName}}Dto) {
    const { getAll, limit, page } = filter;
    const skip = (page - 1) * limit;
    const findOptions: FindManyOptions<{{EntityName}}> = {
      order: { createdAt: 'DESC' },
    };

    if (!getAll) {
      findOptions.skip = skip;
      findOptions.take = limit;
    }

    if (filter.search) {
      findOptions.where = [
        // Add searchable fields here based on your entity
        // { name: Like(\`%\${filter.search}%\`) },
        // { description: Like(\`%\${filter.search}%\`) },
      ];
    }

    const [data, total] = await this.{{camelCaseName}}Repository.findAndCount(findOptions);

    return {
      data,
      total,
      page,
      limit,
    };
  }

  async findOne(id: string) {
    const {{camelCaseName}} = await this.{{camelCaseName}}Repository.findOne({
      where: { id },
    });
    if (!{{camelCaseName}}) {
      throw new NotFoundException(\`{{EntityName}} with ID '\${id}' not found\`);
    }

    return {{camelCaseName}};
  }

  async update(id: string, update{{EntityName}}Dto: Update{{EntityName}}Dto) {
    // Check if {{entityName}} exists
    const existing{{EntityName}} = await this.findOne(id);

    // Add any additional validation here
    // if (update{{EntityName}}Dto.someField && update{{EntityName}}Dto.someField !== existing{{EntityName}}.someField) {
    //   const duplicate{{EntityName}} = await this.{{camelCaseName}}Repository.findOne({
    //     where: { someField: update{{EntityName}}Dto.someField },
    //   });
    //   if (duplicate{{EntityName}}) {
    //     throw new ConflictException(
    //       \`{{EntityName}} with this field already exists\`,
    //     );
    //   }
    // }

    // Update the {{entityName}}
    const updated{{EntityName}} = await this.{{camelCaseName}}Repository.preload({
      id,
      ...update{{EntityName}}Dto,
    });

    if (!updated{{EntityName}}) {
      throw new NotFoundException(\`{{EntityName}} with ID '\${id}' not found\`);
    }

    return await this.{{camelCaseName}}Repository.save(updated{{EntityName}});
  }

  async remove(id: string) {
    const {{camelCaseName}} = await this.findOne(id);
    await this.{{camelCaseName}}Repository.remove({{camelCaseName}});
    return {
      message: \`{{EntityName}} with ID '\${id}' has been successfully deleted\`,
    };
  }
}
`;
