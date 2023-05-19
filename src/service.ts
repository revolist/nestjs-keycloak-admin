import { Logger, Global } from '@nestjs/common'
import { Client, Issuer, TokenSet } from 'openid-client'
import { resolve } from 'url'
import { ResourceManager } from './lib/resource-manager'
import { PermissionManager } from './lib/permission-manager'
import { KeycloakModuleOptions } from './@types/package'
import KeycloakConnect, { Keycloak } from 'keycloak-connect'
import { RequestManager } from './lib/request-manager'
import { UMAConfiguration } from './@types/uma'

@Global()
export class KeycloakService {
  private logger = new Logger(KeycloakService.name)

  private tokenSet?: TokenSet
  private issuerClient?: Client

  private baseUrl: string
  private requestManager!: RequestManager
  public umaConfiguration?: UMAConfiguration
  public readonly options: KeycloakModuleOptions

  public connect: Keycloak
  public permissionManager!: PermissionManager
  public resourceManager!: ResourceManager
  public client: any

  private tokenAttempt = 0

  constructor(options: KeycloakModuleOptions) {
    if (!options.baseUrl.startsWith('http')) {
      throw new Error(`Invalid base url. It should start with either http or https.`)
    }
    this.options = options
    this.baseUrl = resolve(options.baseUrl, `/realms/${options.realmName}`)

    const keycloak: any = new KeycloakConnect({}, {
      resource: this.options.clientId,
      realm: this.options.realmName,
      'auth-server-url': this.options.baseUrl,
      secret: this.options.clientSecret,
    } as any)

    keycloak.accessDenied = (req: any, _res: any, next: any) => {
      req.accessDenied = true
      next()
    }

    this.connect = keycloak as Keycloak

  }

  async start() {
      const { default: AdminClient } = await (eval(`import('@keycloak/keycloak-admin-client')`));
      this.client = new AdminClient({
        baseUrl: this.options.baseUrl,
        realmName: this.options.realmName,
      });
      this.requestManager = new RequestManager(this, this.baseUrl)
  }

  async initialize(): Promise<void> {
    if (this.umaConfiguration) {
      this.logger.verbose(`Keycloak client configuration preset`)
      return
    }
    this.logger.verbose(`Initializing Keycloak client`)
    await this.start();
    this.logger.verbose(`Connecting Keycloak ResourceManager`)
    const { clientId, clientSecret } = this.options
    
    try {
      const { data } = await this.requestManager.get<UMAConfiguration>(
        '/.well-known/uma2-configuration'
      )
      this.umaConfiguration = data
      this.resourceManager = new ResourceManager(this, data.resource_registration_endpoint)
    } catch (err) {
      this.logger.error(err)
      throw err
    }
    this.permissionManager = new PermissionManager(this, this.umaConfiguration.token_endpoint)

    const keycloakIssuer = await Issuer.discover(this.umaConfiguration.issuer)

    this.issuerClient = new keycloakIssuer.Client({
      client_id: clientId,
      client_secret: clientSecret,
    })

    this.logger.verbose(`Connecting client_credentials`)
    this.tokenSet = await this.issuerClient.grant({
      clientId,
      clientSecret,
      grant_type: 'client_credentials',
    })

    if (this.tokenSet?.access_token) this.client.setAccessToken(this.tokenSet?.access_token)

    if (this.tokenSet.expires_at) {
      this.logger.verbose(`Initial token expires at ${this.tokenSet.expires_at}`)
    }
  }
  async refreshGrant(): Promise<TokenSet | undefined | null> {
    if (!this.tokenSet) {
      if (this.tokenAttempt < 3) {
        await this.initialize()
      }
      this.logger.debug(`Refresh token not set.`)
      return undefined
    }

    if (!this.tokenSet?.expired()) {
      this.logger.debug(`Refresh tokenexpired.`)
      return undefined
    }
    this.tokenAttempt = 0
    if (!this.tokenSet.refresh_token) {
      this.logger.debug(`Refresh token is missing. Reauthenticating.`)

      this.tokenSet = await this.issuerClient?.grant({
        clientId: this.options.clientId,
        clientSecret: this.options.clientSecret,
        grant_type: 'client_credentials',
      })
      if (this.tokenSet?.access_token) {
        this.client.setAccessToken(this.tokenSet?.access_token)
      }

      return this.tokenSet
    }

    this.logger.debug(`Refreshing grant token`)

    this.tokenSet = await this.issuerClient?.refresh(this.tokenSet.refresh_token)

    return this.tokenSet
  }
}
