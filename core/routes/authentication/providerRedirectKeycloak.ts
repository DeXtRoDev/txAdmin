import {getKeycloakRedirectUrl} from './oauthMethods';
import {InitializedCtx} from "@modules/WebServer/ctxTypes";
import {ApiOauthRedirectResp} from "@shared/authApiTypes";
import {z} from "zod";

const querySchema = z.object({
    origin: z.string(),
});

export default async function AuthKeycloakProviderRedirect(ctx: InitializedCtx) {
    const schemaRes = querySchema.safeParse(ctx.request.query);
    if (!schemaRes.success) {
        return ctx.send<ApiOauthRedirectResp>({
            error: `Invalid request query: ${schemaRes.error.message}`,
        });
    }
    const {origin} = schemaRes.data;

    //Check if there are already admins set up
    if (!txCore.adminStore.hasAdmins()) {
        return ctx.send<ApiOauthRedirectResp>({
            error: `no_admins_setup`,
        });
    }

    return ctx.send<ApiOauthRedirectResp>({
        authUrl: getKeycloakRedirectUrl(ctx, origin),
    });
};
