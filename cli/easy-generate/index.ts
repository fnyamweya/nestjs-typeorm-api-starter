#!/usr/bin/env node

import { Command } from 'commander';
import { generateModule } from './commands/generate-module';
import { generateService } from './commands/generate-service';
import { generateController } from './commands/generate-controller';

const program = new Command();

program
  .name('easy-generate')
  .description(
    'Easy Generate CLI - Generate CRUD modules, services, and controllers',
  )
  .version('1.0.0');

program
  .command('make:module <name>')
  .description(
    'Generate a complete CRUD module with entity, DTOs, service, and controller',
  )
  .option(
    '-p, --path <path>',
    'Specify the path where the module should be created',
    'src',
  )
  .action((name, options) => {
    generateModule(name, options.path);
  });

// Generate service command
program
  .command('make:service <name>')
  .description('Generate a service with CRUD operations')
  .option(
    '-p, --path <path>',
    'Specify the path where the service should be created',
    'src',
  )
  .action((name, options) => {
    generateService(name, options.path);
  });

// Generate controller command
program
  .command('make:controller <name>')
  .description('Generate a controller with CRUD endpoints')
  .option(
    '-p, --path <path>',
    'Specify the path where the controller should be created',
    'src',
  )
  .action((name, options) => {
    generateController(name, options.path);
  });

program.parse();
