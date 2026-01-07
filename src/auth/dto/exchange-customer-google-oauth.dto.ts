import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class ExchangeCustomerGoogleOAuthDto {
  @ApiProperty({
    description: 'Authorization code returned by Google to the customer UI callback',
    example: '4/0AbcDefGhIjKlMnOpQrStUvWxYz',
  })
  @IsString()
  @IsNotEmpty()
  code: string;

  @ApiProperty({
    description:
      'Optional PKCE code verifier (if the customer UI uses PKCE). Not required for confidential clients.',
    required: false,
    example: 'z3A...your_code_verifier...',
  })
  @IsString()
  @IsOptional()
  codeVerifier?: string;
}
