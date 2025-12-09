import * as fs from 'fs';
import * as path from 'path';

export class FileUtils {
  static ensureDirectoryExists(dirPath: string): void {
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
    }
  }

  static writeFile(filePath: string, content: string): void {
    const dir = path.dirname(filePath);
    this.ensureDirectoryExists(dir);
    fs.writeFileSync(filePath, content, 'utf8');
  }

  static fileExists(filePath: string): boolean {
    return fs.existsSync(filePath);
  }

  static readFile(filePath: string): string {
    return fs.readFileSync(filePath, 'utf8');
  }

  static toPascalCase(str: string): string {
    return str
      .split(/[-_\s]+/)
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join('');
  }

  static toCamelCase(str: string): string {
    const pascalCase = this.toPascalCase(str);
    return pascalCase.charAt(0).toLowerCase() + pascalCase.slice(1);
  }

  static toKebabCase(str: string): string {
    return str
      .replace(/([a-z])([A-Z])/g, '$1-$2')
      .replace(/[\s_]+/g, '-')
      .toLowerCase();
  }

  static toSnakeCase(str: string): string {
    return str
      .replace(/([a-z])([A-Z])/g, '$1_$2')
      .replace(/[\s-]+/g, '_')
      .toLowerCase();
  }

  static pluralize(str: string): string {
    if (
      str.endsWith('y') &&
      !['a', 'e', 'i', 'o', 'u'].includes(str[str.length - 2])
    ) {
      return str.slice(0, -1) + 'ies';
    }
    if (
      str.endsWith('s') ||
      str.endsWith('sh') ||
      str.endsWith('ch') ||
      str.endsWith('x') ||
      str.endsWith('z')
    ) {
      return str + 'es';
    }
    return str + 's';
  }
}
