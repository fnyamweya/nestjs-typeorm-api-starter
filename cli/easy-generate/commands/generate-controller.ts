import * as path from 'path';
import { FileUtils } from '../utils/file-utils';

export async function generateController(
  name: string,
  basePath: string = 'src',
): Promise<void> {
  const kebabCaseName = FileUtils.toKebabCase(name);
  const pascalCaseName = FileUtils.toPascalCase(name);
  const camelCaseName = FileUtils.toCamelCase(name);
  const modulePath = path.join(basePath, kebabCaseName);
  const controllersPath = path.join(modulePath, 'controllers');
  const controllerPath = path.join(
    controllersPath,
    `${kebabCaseName}.controller.ts`,
  );
  const entityFileName = FileUtils.pluralize(name);

  // Check if entity exists
  const entityPath = path.join(
    modulePath,
    'entities',
    `${entityFileName}.entity.ts`,
  );
  if (!FileUtils.fileExists(entityPath)) {
    console.error(
      '❌ Entity not found. Please create the entity first or use make:module to generate the complete module.',
    );
    return;
  }

  // Check if service exists
  const servicePath = path.join(
    modulePath,
    'services',
    `${kebabCaseName}.service.ts`,
  );
  if (!FileUtils.fileExists(servicePath)) {
    console.error(
      '❌ Service not found. Please create the service first or use make:module to generate the complete module.',
    );
    return;
  }

  // Check if required DTOs exist
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
    console.error(`   - ${createDtoPath}`);
    console.error(`   - ${updateDtoPath}`);
    console.error(`   - ${filterDtoPath}`);
    return;
  }

  // Check if controller already exists
  if (FileUtils.fileExists(controllerPath)) {
    console.error(
      `❌ Controller already exists at ${controllerPath}. Use a different name or delete the existing file.`,
    );
    return;
  }

  // Read and process template
  const templatePath = path.join(
    __dirname,
    '..',
    'templates',
    'controller.template.ts',
  );
  let template = FileUtils.readFile(templatePath);

  // Replace placeholders
  template = template
    .replace(/{{EntityName}}/g, pascalCaseName)
    .replace(/{{entityName}}/g, camelCaseName)
    .replace(/{{kebab-case-name}}/g, kebabCaseName)
    .replace(/{{PluralEntityName}}/g, FileUtils.toPascalCase(entityFileName));

  // Ensure directory exists and write file
  FileUtils.ensureDirectoryExists(controllersPath);
  FileUtils.writeFile(controllerPath, template);

  console.log(`✅ Controller generated successfully at ${controllerPath}`);
  console.log('\n📋 Next steps:');
  console.log(
    '   1. Review the generated controller and customize validation rules',
  );
  console.log('   2. Update the module file to include the new controller');
  console.log('   3. Test the endpoints and adjust permissions as needed');
}
