import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return `${process.env.APP_NAME}! Have a good day my friend 😊.`;
  }
}
