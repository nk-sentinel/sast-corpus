import { Controller, Get, Query } from '@nestjs/common';

import { archive } from './runner';

@Controller('reports')
export class ReportsController {
  @Get()
  show(@Query('name') name: string): unknown {
    return archive(name);
  }
}
