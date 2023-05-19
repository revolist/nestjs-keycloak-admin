import { DynamicModule, Module, Provider, Global } from '@nestjs/common'
import { KEYCLOAK_ADMIN_OPTIONS } from './constants'
import { KeycloakService } from './service'
import { KeycloakModuleOptions, KeycloakModuleAsyncOptions } from './@types/package'

@Global()
@Module({
  providers: [KeycloakService],
  exports: [KeycloakService],
})
export class KeycloakModule {
  public static registerAsync(options: KeycloakModuleAsyncOptions): DynamicModule {
    const customOptions = this.getCustomOptions(options)

    return {
      module: KeycloakModule,
      imports: options.imports || [],
      providers: [customOptions, this.keycloakProvider],
      exports: [customOptions, this.keycloakProvider],
    }
  }

  private static getCustomOptions(options: KeycloakModuleAsyncOptions): Provider {
    return {
      provide: KEYCLOAK_ADMIN_OPTIONS,
      useFactory: options.useFactory,
      inject: options.inject || [],
    }
  }

  private static keycloakProvider: Provider = {
    provide: KeycloakService,
    useFactory: async (options: KeycloakModuleOptions) => {
      const client = new KeycloakService(options);
      await client.initialize()
      return client
    },
    inject: [KEYCLOAK_ADMIN_OPTIONS],
  }

  private static getOptionsProvider(options: KeycloakModuleOptions): Provider {
    return {
      provide: KEYCLOAK_ADMIN_OPTIONS,
      useValue: options,
    }
  }
}
