@Controller('a')
export class A {
  // ruleid: nest-escritura-sin-roles
  @Post()
  crear() {}

  // ruleid: nest-escritura-sin-roles
  @Put(':id')
  async editar(@Param('id') id: string) {}

  // ruleid: nest-escritura-sin-roles
  @All('x')
  todos() {}

  // ruleid: nest-escritura-sin-roles
  @Post()
  @HttpCode(200)
  conOtroDecorador() {}

  // ok: nest-escritura-sin-roles
  @Roles('admin')
  @Post()
  creaOk() {}

  // ok: nest-escritura-sin-roles
  @Delete(':id')
  @Roles('admin')
  borraOk() {}

  // ok: nest-escritura-sin-roles
  @Public()
  @Post('login')
  login() {}

  // ok: nest-escritura-sin-roles
  @Post('login2')
  @Public()
  login2() {}

  // ok: nest-escritura-sin-roles
  @Get()
  leer() {}

  // ok: nest-escritura-sin-roles
  @Post('z')
  @UseGuards(AuthGuard)
  @Roles('admin')
  limiteConTresDecoradores() {}
}

@Roles('admin')
@Controller('b')
export class B {
  // ok: nest-escritura-sin-roles
  @Post()
  claseConRoles() {}
}
