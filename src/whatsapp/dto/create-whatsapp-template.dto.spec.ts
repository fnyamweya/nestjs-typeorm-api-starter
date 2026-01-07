import 'reflect-metadata';

import { plainToInstance } from 'class-transformer';
import { validateSync } from 'class-validator';
import { CreateWhatsappTemplateDto } from './create-whatsapp-template.dto';

describe('CreateWhatsappTemplateDto', () => {
  it('accepts JSON object arrays for components/defaultComponents', () => {
    const dto = plainToInstance(CreateWhatsappTemplateDto, {
      name: 'order_confirmation_v2',
      language: 'en_US',
      category: 'UTILITY',
      components: [{ type: 'BODY', text: 'Hi {{1}}' }],
      defaultComponents: [
        { type: 'body', parameters: [{ type: 'text', text: 'Customer' }] },
      ],
      isActive: true,
      metaJson: { scenario: 'order-confirmed' },
      submitToProvider: false,
    });

    const errors = validateSync(dto, {
      whitelist: true,
      forbidNonWhitelisted: true,
    });
    expect(errors).toEqual([]);
  });

  it('rejects invalid Meta BODY components (missing text)', () => {
    const dto = plainToInstance(CreateWhatsappTemplateDto, {
      name: 'order_confirmation_v2',
      category: 'UTILITY',
      components: [{ type: 'BODY' }],
    });

    const errors = validateSync(dto, {
      whitelist: true,
      forbidNonWhitelisted: true,
    });
    expect(errors.length).toBeGreaterThan(0);
  });

  it('coerces category to uppercase and trims', () => {
    const dto = plainToInstance(CreateWhatsappTemplateDto, {
      name: '  order_confirmation_v2  ',
      category: ' utility ',
      components: [{ type: 'BODY', text: 'Hi {{1}}' }],
    });

    const errors = validateSync(dto, {
      whitelist: true,
      forbidNonWhitelisted: true,
    });
    expect(errors).toEqual([]);
    expect(dto.name).toBe('order_confirmation_v2');
    expect(dto.category).toBe('UTILITY');
  });
});
