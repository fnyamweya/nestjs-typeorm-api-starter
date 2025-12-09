import { PartialType } from '@nestjs/mapped-types';
import { Create{{entityName}}Dto } from './create-{{kebabCaseName}}.dto';

export class Update{{entityName}}Dto extends PartialType(Create{{entityName}}Dto) {}