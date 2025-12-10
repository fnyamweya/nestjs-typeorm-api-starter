/**
 * Authors:
 *   - Arkar Min <arkarmin@example.com>
 * Date: 2025-01-20
 * Description: OBS CRM Backend - Disable Two Factor Authentication DTO
 */

import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class DisableTwoFactorDto {
  @ApiProperty({
    description: 'Current account password used to confirm 2FA disablement',
    example: 'Curr3ntP@ss',
  })
  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required to disable 2FA' })
  password: string;
}
