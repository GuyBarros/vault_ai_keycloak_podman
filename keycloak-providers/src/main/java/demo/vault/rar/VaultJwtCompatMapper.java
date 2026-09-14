package demo.vault.rar;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
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
 * <p>RFC 8693 {@code act} is copied from form {@code delegation_act} (JSON)
 * or synthesized from {@code delegation_actor} (Vault identity JWT). Keycloak
 * cannot verify a Vault-issued actor token as {@code actor_token}, so the
 * broker sends these custom fields instead. {@code act.sub} is the SPIFFE ID
 * (Vault OAuth RS alias name); {@code act.spiffe_id} repeats it for the inspector.
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
    private static final String ACT_CLAIM = "act";
    private static final String DELEGATION_ACT = "delegation_act";
    private static final String DELEGATION_ACTOR = "delegation_actor";
    private static final String SPIFFE_PREFIX = "spiffe://example.org/";
    private static final String PAR_NOTE = "client_request_param_authorization_details";
    private static final String RAR_TYPE = "vault:path_access";
    private static final String READ_PATH = "database/creds/user-mcp-read-role";
    private static final String WRITE_PATH = "database/creds/user-mcp-write-role";
    private static final String TRANSFORM_PATH = "transform/encode/user-mcp-transform";
    private static final String LEASE_REVOKE_PATH = "sys/leases/revoke";

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
        Map<String, Object> act = actClaim(session);
        if (act != null && !act.isEmpty()) {
            token.setOtherClaims(ACT_CLAIM, act);
        }
        return token;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> actClaim(KeycloakSession session) {
        String raw = formParam(session, DELEGATION_ACT);
        if (raw != null && !raw.isBlank()) {
            try {
                JsonNode node = JsonSerialization.mapper.readTree(raw);
                if (node != null && node.isObject()) {
                    return JsonSerialization.mapper.convertValue(node, Map.class);
                }
            } catch (Exception ignored) {
                // fall through to actor JWT
            }
        }
        String actorJwt = formParam(session, DELEGATION_ACTOR);
        if (actorJwt == null || actorJwt.isBlank()) {
            return null;
        }
        return actFromActorJwt(actorJwt);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> actFromActorJwt(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) {
                return null;
            }
            byte[] decoded = Base64.getUrlDecoder().decode(pad(parts[1]));
            JsonNode payload = JsonSerialization.mapper.readTree(
                    new String(decoded, StandardCharsets.UTF_8));
            if (payload == null || !payload.isObject()) {
                return null;
            }
            Map<String, Object> act = new LinkedHashMap<>();
            String agentId = text(payload, "agent_id");
            String entitySub = text(payload, "sub");
            if (agentId == null || agentId.isBlank()) {
                agentId = entitySub;
            }
            if (agentId == null || agentId.isBlank()) {
                return null;
            }
            String spiffe = agentId.startsWith("spiffe://") ? agentId : SPIFFE_PREFIX + agentId;
            act.put("sub", spiffe);
            act.put("spiffe_id", spiffe);
            String iss = text(payload, "iss");
            if (iss != null && !iss.isBlank()) {
                act.put("iss", iss);
            }
            act.put("agent_id", agentId);
            return act;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isTextual() ? value.asText() : null;
    }

    private static String pad(String b64) {
        int rem = b64.length() % 4;
        if (rem == 0) {
            return b64;
        }
        return b64 + "====".substring(rem);
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
        boolean needsTransform = false;
        for (String part : scope.split("\\s+")) {
            if ("users.read".equals(part)) {
                details.add(pathAccess(READ_PATH, List.of("read")));
                needsTransform = true;
            } else if ("users.write".equals(part)) {
                details.add(pathAccess(WRITE_PATH, List.of("read")));
                needsTransform = true;
            }
        }
        if (needsTransform) {
            details.add(pathAccess(TRANSFORM_PATH, List.of("create", "update")));
            details.add(pathAccess(LEASE_REVOKE_PATH, List.of("update")));
        }
        return details;
    }

    private static Map<String, Object> pathAccess(String path, List<String> capabilities) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("type", RAR_TYPE);
        entry.put("path", path);
        entry.put("capabilities", capabilities);
        return entry;
    }
}
