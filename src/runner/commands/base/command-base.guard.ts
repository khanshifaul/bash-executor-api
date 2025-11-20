import { Injectable } from '@nestjs/common';
import { RoleGuard } from '../../../common/guards/role.guard';

@Injectable()
export class CommandBaseGuard extends RoleGuard {}