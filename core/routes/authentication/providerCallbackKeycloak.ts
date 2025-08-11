import {handleKeycloakCallback} from './oauthMethods';
import {InitializedCtx} from "@modules/WebServer/ctxTypes";
import {ApiOauthCallbackErrorResp, ApiOauthCallbackResp, ReactAuthDataType} from "@shared/authApiTypes";
import {z} from "zod";
import {AuthedAdmin, KeycloakSessAuthType} from "@modules/WebServer/authLogic";

const bodySchema = z.object({
    redirectUri: z.string(),
});

export default async function AuthKeycloakProviderCallback(ctx: InitializedCtx) {
    const schemaRes = bodySchema.safeParse(ctx.request.body);
    if (!schemaRes.success) {
        return ctx.send<ApiOauthCallbackResp>({
            errorTitle: 'Invalid request body',
            errorMessage: schemaRes.error.message,
        });
    }
    const { redirectUri } = schemaRes.data;

    //Handling the callback
    const callbackResp = await handleKeycloakCallback(ctx, redirectUri);
    if('errorCode' in callbackResp || 'errorTitle' in callbackResp){
        return ctx.send<ApiOauthCallbackErrorResp>(callbackResp);
    }
    const userInfo = callbackResp;

    //Getting identifier
    const username = userInfo.preferred_username
    if(!username){
        return ctx.send<ApiOauthCallbackResp>({
            errorTitle: 'Invalid preferred_username identifier.',
            errorMessage: 'Could not extract the user identifier from Keycloak',
        });
    }

    //Getting Keycloak roles
    const roles: string[] = userInfo.realm_access?.roles
        ?? userInfo.resource_access?.[process.env.KC_CLIENT_ID!].roles
        ?? [];
    if(!roles) {
        return ctx.send<ApiOauthCallbackResp>({
            errorTitle: 'Missing Keycloak roles.',
            errorMessage: 'Could not extract roles from Keycloak',
        });
    }

    const kcAdminRole = process.env.KC_ADMIN_ROLE ?? 'txadmin_admin'
    const isKcAdmin = roles.map(r => r.toLowerCase()).includes(kcAdminRole);

    //Check & Login user
    try {
        let vaultAdmin = txCore.adminStore.getAdminByIdentifiers([username]);

        if (!isKcAdmin) {
            if (vaultAdmin) {
                await txCore.adminStore.deleteAdmin(username);
            }
        } else {
            if (!vaultAdmin) {
                await txCore.adminStore.addKeycloakAdmin(username, username, []);
            }
        }

        vaultAdmin = txCore.adminStore.getAdminByIdentifiers([username]);
        if (!vaultAdmin) {
            ctx.sessTools.destroy();
            return ctx.send<ApiOauthCallbackResp>({
                errorCode: 'not_admin',
                errorContext: {
                    identifier: username,
                    name: userInfo.name ?? username,
                    profile: "",
                }
            });
        }

        //Setting session
        const sessData = {
            type: 'keycloak',
            username: vaultAdmin.name,
            csrfToken: txCore.adminStore.genCsrfToken(),
            expiresAt: Date.now() + 86_400_000, //24h,
            identifier: username,
        } satisfies KeycloakSessAuthType;
        ctx.sessTools.set({ auth: sessData });

        //If the user has a picture, save it to the cache
        if (userInfo.picture) {
            txCore.cacheStore.set(`admin:picture:${vaultAdmin.name}`, userInfo.picture);
        }

        const authedAdmin = new AuthedAdmin(vaultAdmin, sessData.csrfToken);
        authedAdmin.logAction(`logged in from ${ctx.ip} via keycloak`);
        txCore.metrics.txRuntime.loginOrigins.count(ctx.txVars.hostType);
        txCore.metrics.txRuntime.loginMethods.count('keycloak');
        return ctx.send<ReactAuthDataType>(authedAdmin.getAuthData());
    } catch (error) {
        ctx.sessTools.destroy();
        console.verbose.error(`Failed to login: ${(error as Error).message}`);
        return ctx.send<ApiOauthCallbackResp>({
            errorTitle: 'Failed to login:',
            errorMessage: (error as Error).message,
        });
    }
};
