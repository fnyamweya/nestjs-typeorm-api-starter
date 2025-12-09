import * as path from 'path';
import { FileUtils } from '../utils/file-utils';
import { serviceTemplate } from '../templates/service.template';

export function generateService(name: string, basePath: string = 'src'): void {
  const entityName = FileUtils.toPascalCase(name);
  const camelCaseName = FileUtils.toCamelCase(name);
  const kebabCaseName = FileUtils.toKebabCase(name);
  const entityFileName = kebabCaseName;

  // Define paths
  const modulePath = path.join(basePath, kebabCaseName);
  const servicesPath = path.join(modulePath, 'services');
  const serviceFilePath = path.join(
    servicesPath,
    `${kebabCaseName}.service.ts`,
  );

  // Check if entity exists
  const entityPath = path.join(
    modulePath,
    'entities',
    `${entityFileName}.entity.ts`,
  );
  if (!FileUtils.fileExists(entityPath)) {
    console.error(`❌ Entity file not found: ${entityPath}`);
    console.log(
      'Please create the entity first or use make:module to generate the complete module.',
    );
    return;
  }

  // Check if DTOs exist
  const createDtoPath = path.join(
    modulePath,
    'dto',
    `create-${kebabCaseName}.dto.ts`,
  );
  const updateDtoPath = path.join(
    modulePath,
    'dto',
    `update-${kebabCaseName}.dto.ts`,
  );
  const filterDtoPath = path.join(
    modulePath,
    'dto',
    `filter-${kebabCaseName}.dto.ts`,
  );

  if (
    !FileUtils.fileExists(createDtoPath) ||
    !FileUtils.fileExists(updateDtoPath) ||
    !FileUtils.fileExists(filterDtoPath)
  ) {
    console.error(
      '❌ Required DTOs not found. Please ensure the following files exist:',
    );
    console.log(`  - ${createDtoPath}`);
    console.log(`  - ${updateDtoPath}`);
    console.log(`  - ${filterDtoPath}`);
    return;
  }

  // Check if service already exists
  if (FileUtils.fileExists(serviceFilePath)) {
    console.error(`❌ Service already exists: ${serviceFilePath}`);
    return;
  }

  // Generate service content
  const serviceContent = serviceTemplate
    .replace(/{{EntityName}}/g, entityName)
    .replace(/{{camelCaseName}}/g, camelCaseName)
    .replace(/{{kebabCaseName}}/g, kebabCaseName)
    .replace(/{{entityFileName}}/g, entityFileName)
    .replace(/{{entityName}}/g, camelCaseName);

  // Write service file
  FileUtils.writeFile(serviceFilePath, serviceContent);

  console.log(`✅ Service generated successfully:`);
  console.log(`   ${serviceFilePath}`);
  console.log('');
  console.log('📝 Next steps:');
  console.log(
    '   1. Review the generated service and customize validation logic',
  );
  console.log(
    '   2. Update the search fields in findAll method based on your entity',
  );
  console.log('   3. Add any additional business logic as needed');
}
