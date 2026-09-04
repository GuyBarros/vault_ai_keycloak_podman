package demo.vault.rar;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Makes Keycloak-issued access tokens usable as Vault OAuth Resource Server
 * credentials with RFC 9396 RAR ({@code authorization_details}).
 *
 * <p>Keycloak always writes a payload {@code typ} claim ({@code Bearer}) in
 * {@code TokenManager.initToken()}. Vault's OAuth RS JWT schema rejects that
 * body claim. RFC 9068 puts {@code typ} in the <em>header</em> only
 * ({@code at+jwt}), which is already handled by the client attribute
 * {@code access.token.header.type.rfc9068}. This mapper clears the payload
 * claim.
 *
 * <p>RAR is copied into the JWT (Vault reads the claim, not the token
 * endpoint JSON body) from, in order:
 * <ol>
 *   <li>token-endpoint form parameter {@code authorization_details}</li>
 *   <li>PAR/auth-request client-session note {@code client_request_param_authorization_details}</li>
 *   <li>synthesized {@code vault:path_access} entries from {@code users.read}/{@code users.write} scopes</li>
 * </ol>
 */
public class VaultJwtCompatMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {

    public static final String PROVIDER_ID = "oidc-vault-jwt-compat-mapper";
    private static final String AUTH_DETAILS_CLAIM = "authorization_details";
    private static final String PAR_NOTE = "client_request_param_authorization_details";
    private static final String RAR_TYPE = "vault:path_access";
    private static final String READ_PATH = "database/creds/user-mcp-read-role";
    private static final String WRITE_PATH = "database/creds/user-mcp-write-role";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Vault JWT compat (strip typ + RAR)";
    }

    @Override
    public String getHelpText() {
        return "Removes the Keycloak access-token payload typ claim and copies RFC 9396 authorization_details into the JWT so Vault OAuth Resource Server can enforce RAR.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public AccessToken transformAccessToken(
            AccessToken token,
            ProtocolMapperModel mappingModel,
            KeycloakSession session,
            UserSessionModel userSession,
            ClientSessionContext clientSessionCtx) {
        token.type(null);
        if ((token.getSubject() == null || token.getSubject().isBlank())
                && userSession != null
                && userSession.getUser() != null) {
            token.subject(userSession.getUser().getId());
        }

        List<Map<String, Object>> details = firstRarFromRequest(session, clientSessionCtx);
        if (details == null) {
            details = synthesizeFromScopes(clientSessionCtx);
        }
        if (details != null && !details.isEmpty()) {
            token.setOtherClaims(AUTH_DETAILS_CLAIM, details);
        }
        return token;
    }

    private static List<Map<String, Object>> firstRarFromRequest(
            KeycloakSession session, ClientSessionContext clientSessionCtx) {
        String raw = formParam(session, AUTH_DETAILS_CLAIM);
        if (raw == null || raw.isBlank()) {
            raw = clientNote(clientSessionCtx, PAR_NOTE);
        }
        if (raw == null || raw.isBlank()) {
            return null;
        }
        return parseAuthorizationDetails(raw);
    }

    private static String formParam(KeycloakSession session, String name) {
        try {
            if (session == null || session.getContext() == null || session.getContext().getHttpRequest() == null) {
                return null;
            }
            return session.getContext().getHttpRequest().getDecodedFormParameters().getFirst(name);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static String clientNote(ClientSessionContext ctx, String name) {
        if (ctx == null || ctx.getClientSession() == null) {
            return null;
        }
        return ctx.getClientSession().getNote(name);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> parseAuthorizationDetails(String raw) {
        try {
            JsonNode node = JsonSerialization.mapper.readTree(raw);
            if (node == null || node.isNull()) {
                return null;
            }
            if (node.isArray()) {
                return JsonSerialization.mapper.convertValue(node, List.class);
            }
            if (node.isObject()) {
                Map<String, Object> one = JsonSerialization.mapper.convertValue(node, Map.class);
                List<Map<String, Object>> list = new ArrayList<>();
                list.add(one);
                return list;
            }
        } catch (Exception ignored) {
            return null;
        }
        return null;
    }

    private static List<Map<String, Object>> synthesizeFromScopes(ClientSessionContext ctx) {
        if (ctx == null) {
            return null;
        }
        String scope = ctx.getScopeString(true);
        if (scope == null || scope.isBlank()) {
            return null;
        }
        List<Map<String, Object>> details = new ArrayList<>();
        for (String part : scope.split("\\s+")) {
            if ("users.read".equals(part)) {
                details.add(pathAccess(READ_PATH));
            } else if ("users.write".equals(part)) {
                details.add(pathAccess(WRITE_PATH));
            }
        }
        return details;
    }

    private static Map<String, Object> pathAccess(String path) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("type", RAR_TYPE);
        entry.put("path", path);
        entry.put("capabilities", List.of("read"));
        return entry;
    }
}
