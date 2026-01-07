import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  IsIn,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
} from 'class-validator';

const MESSAGE_TYPES = ['template', 'text'] as const;

export class SendWhatsappMessageDto {
  @ApiProperty({
    description: 'Recipient phone number in international format',
    example: '254712345678',
  })
  @IsString()
  @IsNotEmpty()
  to: string;

  @ApiPropertyOptional({
    description: 'Message type',
    enum: MESSAGE_TYPES,
    default: 'template',
  })
  @IsOptional()
  @IsIn(MESSAGE_TYPES)
  type?: string;

  @ApiPropertyOptional({
    description: 'Template ID from local storage',
    example: 'uuid',
  })
  @IsOptional()
  @IsUUID()
  templateId?: string;

  @ApiPropertyOptional({
    description: 'Template name (provider name)',
    example: 'order_confirmation',
  })
  @IsOptional()
  @IsString()
  templateName?: string;

  @ApiPropertyOptional({
    description: 'Template language code',
    example: 'en_US',
  })
  @IsOptional()
  @IsString()
  language?: string;

  @ApiPropertyOptional({
    description: 'Template components with parameters (send-time payload)',
    type: [Object],
  })
  @IsOptional()
  @IsArray()
  @IsObject({ each: true })
  components?: Array<Record<string, unknown>>;

  @ApiPropertyOptional({
    description: 'Text body for session messages',
    example: 'Hello from support',
  })
  @IsOptional()
  @IsString()
  text?: string;
}
