const modulename = 'AdminStore:KeycloakProvider';
import crypto from 'node:crypto';
import {BaseClient, custom, Issuer} from 'openid-client';
import {URL} from 'node:url';
import consoleFactory from '@lib/console';
import {z} from 'zod';

const console = consoleFactory(modulename);

const userInfoSchema = z.object({
    sub: z.string().min(1),
    preferred_username: z.string().min(1),
    email: z.string().optional(),
    name: z.string().optional(),
    picture: z.string().optional(),
    realm_access: z
        .object({
            roles: z.array(z.string()).optional(),
        })
        .optional(),
    resource_access: z
        .record(
            z.string(),
            z.object({
                roles: z.array(z.string()).optional(),
            })
        )
        .optional(),
});
export type KcUserInfo = z.infer<typeof userInfoSchema> & { picture: string | undefined };

const getOauthState = (stateKern: string) => {
    const stateSeed = `tx:keycloak:${stateKern}`;
    return crypto.createHash('SHA1').update(stateSeed).digest('hex');
};

export default class KeycloakProvider {
    private client?: BaseClient;

    constructor() {
        const base = process.env.KC_ISSUER!;
        const kcIssuer = new Issuer({
            issuer: base,
            authorization_endpoint: `${base}/protocol/openid-connect/auth`,
            token_endpoint:         `${base}/protocol/openid-connect/token`,
            userinfo_endpoint:      `${base}/protocol/openid-connect/userinfo`,
            jwks_uri:               `${base}/protocol/openid-connect/certs`,
            // revocation_endpoint:    `${base}/protocol/openid-connect/revoke`,
            // introspection_endpoint: `${base}/protocol/openid-connect/token/introspect`,
            // code_challenge_methods_supported: ['S256', 'plain'],
        });

        this.client = new kcIssuer.Client({
            client_id: process.env.KC_CLIENT_ID!,
            client_secret: process.env.KC_CLIENT_SECRET,
            response_types: ['code'],
        });
        this.client[custom.clock_tolerance] = 2 * 60 * 60;
        custom.setHttpOptionsDefaults({ timeout: 10000 });

        console.ok('Keycloak OIDC client ready (static issuer).');
    }

    getAuthURL(redirectUri: string, stateKern: string) {
        if (!this.client) throw new Error(`${modulename} is not ready`);
        return this.client.authorizationUrl({
            redirect_uri: redirectUri,
            state: getOauthState(stateKern),
            response_type: 'code',
            scope: 'openid profile email',
        });
    }

    async processCallback(redirectUri: string, stateKern: string, fullCallbackUri: string) {
        if (!this.client) throw new Error(`${modulename} is not ready`);
        const params = this.client.callbackParams(new URL(fullCallbackUri).toString());
        if (!params.code) throw new Error('missing authorization code');
        const tokenSet = await this.client.callback(redirectUri, params, {
            state: getOauthState(stateKern),
        });
        if (!tokenSet) throw new Error('tokenSet is undefined');
        return tokenSet;
    }

    async getUserInfo(accessToken: string): Promise<KcUserInfo> {
        if (!this.client) throw new Error(`${modulename} is not ready`);

        //Perform introspection
        const userInfo = await this.client.userinfo(accessToken);
        const parsed = userInfoSchema.parse(userInfo);
        let picture: string | undefined;
        if (typeof userInfo.picture == 'string' && userInfo.picture.startsWith('https://')) {
            picture = userInfo.picture;
        }

        return { ...parsed, picture };
    }
}