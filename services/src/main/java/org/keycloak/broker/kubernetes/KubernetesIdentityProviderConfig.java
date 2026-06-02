package org.keycloak.broker.kubernetes;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.keycloak.broker.oidc.IssuerValidation;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.util.Strings;
import org.keycloak.utils.KeycloakSessionUtil;

import org.apache.http.client.config.RequestConfig;
import org.jboss.logging.Logger;

import static org.keycloak.broker.kubernetes.KubernetesConstants.KUBERNETES_SERVICE_HOST_KEY;
import static org.keycloak.broker.kubernetes.KubernetesConstants.KUBERNETES_SERVICE_PORT_HTTPS_KEY;
import static org.keycloak.broker.kubernetes.KubernetesConstants.SERVICE_ACCOUNT_TOKEN_PATH;


public class KubernetesIdentityProviderConfig extends IdentityProviderModel implements IssuerValidation {

    private static final int DISCOVERY_TIMEOUT_MILLIS = 5000;
    private static final Logger logger = Logger.getLogger(KubernetesIdentityProviderConfig.class);

    public KubernetesIdentityProviderConfig() {
    }

    public KubernetesIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public String getIssuer() {
        return getConfig().get(ISSUER);
    }

    public int getAllowedClockSkew() {
        String allowedClockSkew = getConfig().get(ALLOWED_CLOCK_SKEW);
        if (allowedClockSkew == null || allowedClockSkew.isEmpty()) {
            return 0;
        }
        try {
            return Integer.parseInt(getConfig().get(ALLOWED_CLOCK_SKEW));
        } catch (NumberFormatException e) {
            // ignore it and use default
            return 0;
        }
    }

    @Override
    public Boolean isHideOnLogin() {
        return true;
    }

    @Override
    public void validate(RealmModel realm) {
        super.validate(realm);
        // Persist the discovered service account token issuer before issuer uniqueness validation.
        resolveIssuer();
        validateIssuer(realm, IdentityProviderType.CLIENT_ASSERTION);
    }

    private void resolveIssuer() {
        String issuer = getIssuer();
        if (Strings.isEmpty(issuer)) {
            return;
        }

        boolean inClusterDiscovery = shouldIncludeServiceAccountToken(issuer);

        try {
            KeycloakSession session = KeycloakSessionUtil.getKeycloakSession();
            SimpleHttpRequest request = SimpleHttp.create(session)
                    .withRequestConfig(RequestConfig.custom()
                            .setConnectTimeout(DISCOVERY_TIMEOUT_MILLIS)
                            .setSocketTimeout(DISCOVERY_TIMEOUT_MILLIS)
                            .build())
                    .doGet(discoveryUrl(issuer))
                    .acceptJson();

            if (inClusterDiscovery) {
                String token = getServiceAccountToken();
                if (!Strings.isEmpty(token)) {
                    request.auth(token);
                }
            }

            OIDCConfigurationRepresentation oidcConfig = request.asJson(OIDCConfigurationRepresentation.class);

            if (!Strings.isEmpty(oidcConfig.getIssuer())) {
                getConfig().put(ISSUER, oidcConfig.getIssuer());
            }
        } catch (Exception e) {
            if (inClusterDiscovery) {
                logger.warnf(e, "Failed to resolve Kubernetes issuer from '%s'", issuer);
            } else {
                logger.debugf(e, "Failed to resolve Kubernetes issuer from '%s'", issuer);
            }
        }
    }

    private String discoveryUrl(String issuer) {
        return issuer.replaceAll("/+$", "") + "/.well-known/openid-configuration";
    }

    private String getServiceAccountToken() throws Exception {
        Path path = Path.of(SERVICE_ACCOUNT_TOKEN_PATH);
        if (!Files.exists(path)) {
            return null;
        }

        return Files.readString(path, StandardCharsets.UTF_8);
    }

    private boolean shouldIncludeServiceAccountToken(String issuer) {
        URI uri = URI.create(issuer);
        String host = uri.getHost();
        if (host == null) {
            return false;
        }

        if ("kubernetes".equals(host) || "kubernetes.default".equals(host) || "kubernetes.default.svc".equals(host) || "kubernetes.default.svc.cluster.local".equals(host)) {
            return true;
        }

        String serviceHost = System.getenv(KUBERNETES_SERVICE_HOST_KEY);
        if (!host.equals(serviceHost)) {
            return false;
        }

        String servicePort = System.getenv(KUBERNETES_SERVICE_PORT_HTTPS_KEY);
        int port = uri.getPort();
        // No explicit port means HTTPS default port, which is the Kubernetes API service port.
        return port == -1 || Strings.isEmpty(servicePort) || servicePort.equals(Integer.toString(port));
    }
}
