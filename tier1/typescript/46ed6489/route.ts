import { Controller, Get, Query } from '@nestjs/common';

import { lookup } from './store';

@Controller('reports')
export class ReportsController {
  @Get()
  show(@Query('code') code: string): unknown {
    return lookup(code);
  }
}
