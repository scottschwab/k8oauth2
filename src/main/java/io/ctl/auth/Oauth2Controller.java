package io.ctl.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HttpRequestExecutor;


/**
 * October 10 Freezing development, this code is stuck creating a testing stub
 * for the http call in processAuthorizeRequest().
 */
@RestController
@Component
public class Oauth2Controller {
    public static final String TOKEN_URI = "token_uri";
    public static final String AUTHORIZE_URI = "authorize_uri";
    public static final String CLIENT_ID = "client_id";
    public static final String GRANT_TYPE = "grant_type";
    public static final String RESPONSE_TYPE = "response_type";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String SUCCESS_URI = "success_uri";
    public static final String FAILURE_URI = "failure_uri";
    public static final String SCOPE = "scope";
    public static final String CLIENT_SECRET = "client_secret";

    // configuration files written into the deployment
    public static final String CONFIGMAP_PATH="/etc/auth.configmap";
    public static final String SECRET_PATH="/etc/auth.secret";


    private static Logger LOG = LoggerFactory.getLogger("Oauth2Controller");
    
    // in place so it can be replaced during testing
    @Value("${azure.oauth2.httpExecutor:default}")
    String httpExecutor;

    /* quick test point */
    @RequestMapping("/hi")
    public String hi() {
        return "bye";
    }

    @RequestMapping("/login")
    public void login(@RequestParam(value = "id") final String callerId, final HttpServletResponse response) {
        LOG.info("inside of login");
        try {
            response.setHeader("Location", buildRedirectForOauth2Pages(callerId));
            response.setStatus(302);
        } catch (final URISyntaxException use) {
        }
    }

    /**
     * Public mainly for testability
     * 
     * @param id
     * @param successURL
     * @return
     * @throws URISyntaxException
     */
    public static String buildRedirectForOauth2Pages(final String callerId) throws URISyntaxException {

        final Map<String, String> settings = getAuthInfoFromDeploymentFile(callerId, CONFIGMAP_PATH);
        LOG.info(String.format("Redirect URI is %s", settings.get(REDIRECT_URI)));

        final URI uri = new URIBuilder(new URI(settings.get(AUTHORIZE_URI)))
                .setParameter("client_id", settings.get(CLIENT_ID)).setParameter("scope", settings.get(SCOPE))
                .setParameter("state", callerId).setParameter("response_type", settings.get(RESPONSE_TYPE))
                .setParameter("redirect_uri", settings.get(REDIRECT_URI)).build();

        LOG.info("url generated is " + uri.toASCIIString());
        return uri.toASCIIString();
    }

    /**
     * This endpoint is call by Azure, duriong the oauth2 verfification process.
     * 
     * @param code  A code to use in a lookup, created by Azure
     * @param state The id passed along with request, used to tie results back to
     *              initial request.
     */
    @RequestMapping("/authorize")
    public int authorize(@RequestParam(value = "code") final String code,
            @RequestParam(value = "state") final String callerId, final HttpServletResponse servletResponse) {

        LOG.info(String.format("code back [%s]", code));
        LOG.info(String.format("state / callerId [%s]", callerId));

        final Gson gson = new Gson();

        final Map<String, String> settings = getAuthInfoFromDeploymentFile(callerId, CONFIGMAP_PATH);
        final Map<String, String> secrets = getAuthInfoFromDeploymentFile(callerId, SECRET_PATH);

        try {
            final URI uri = new URI(settings.get(TOKEN_URI));

            final HttpClientBuilder clientBuilder = HttpClientBuilder.create();
            if (httpExecutor != "default") {
                clientBuilder.setRequestExecutor((HttpRequestExecutor) Class.forName(httpExecutor).newInstance());
            }

            final CloseableHttpClient httpclient = clientBuilder.build();
            final HttpPost httppost = new HttpPost(uri);
            final List<NameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("client_id", settings.get(CLIENT_ID)));
            params.add(new BasicNameValuePair("client_secret", secrets.get(CLIENT_SECRET)));
            params.add(new BasicNameValuePair("code", code));
            params.add(new BasicNameValuePair("state", callerId));
            params.add(new BasicNameValuePair("grant_type", settings.get(GRANT_TYPE)));
            params.add(new BasicNameValuePair("redirect_uri", settings.get(REDIRECT_URI)));
            httppost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));

            LOG.info("target url for access token");
            LOG.info(httppost.toString());

            LOG.info("about to use the httpclient");
            final CloseableHttpResponse localResponse = httpclient.execute(httppost);
            LOG.info("pass using the httpclient");
            final HttpEntity entity = localResponse.getEntity();

            if (entity != null) {
                final byte messageBack[] = IOUtils.toByteArray(entity.getContent());

                final String messageString = new String(messageBack, StandardCharsets.UTF_8);
                final Map unpacked = gson.fromJson(messageString, Map.class);
                final String accessToken = (String) unpacked.get("access_token");
                LOG.info("access token");
                LOG.info(accessToken);

                final AccessInformation accessInfo = new AccessInformation();
                accessInfo.accessToken = accessToken;
                accessInfo.username = getNameFromAccessToken(accessToken);
                accessInfo.userEmail = getEmailFromAccessToken(accessToken);
                accessInfo.expirationTime = getExpirationTime(accessToken);

                LOG.info(accessToken);
                final String secretResponse = gson.toJson(accessInfo);
                final String infoFile = exportAccessInfo(secretResponse);
                final URI redirectURI = new URIBuilder(settings.get(SUCCESS_URI)).addParameter("infofile", infoFile)
                        .build();
                servletResponse.sendRedirect(redirectURI.toString());
            } else {
                servletResponse.sendRedirect(settings.get(FAILURE_URI));

            }
            localResponse.close();
            httpclient.close();
        } catch (final Exception e) {
            LOG.error("exception thrown " + e.getMessage());
            try {
                servletResponse.sendRedirect(settings.get(FAILURE_URI));
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }
        return 500;
    }

    /**
     * Verifies the token is valid and still valid.
     * 
     * TODO: use JWT's verify method, which requires an algorithm and additional
     * information to check encryption. see
     * https://static.javadoc.io/com.auth0/java-jwt/3.2.0/com/auth0/jwt/JWTVerifier.html
     * 
     * @param accessToken
     * @return true if token still good
     */
    public static boolean isAccessTokenValid(final String accessToken) {
        final DecodedJWT jwt = JWT.decode(accessToken);
        final Date now = new Date();
        return now.before(jwt.getExpiresAt());
    }

    /**
     * Given a token, pull the name from claims
     * 
     * @param accessToken
     * @return
     */
    public static String getNameFromAccessToken(final String accessToken) throws IllegalAccessException {
        try {
            final DecodedJWT jwt = JWT.decode(accessToken);
            final Map<String, Claim> claims = jwt.getClaims();
            return claims.get("name").asString();
        } catch (final Exception e2) {
            throw new IllegalArgumentException("invalid token passed");
        }
    }

    /**
     * Given a token, pull the username from the claims
     * 
     * @param accessToken
     * @return
     */
    public static String getEmailFromAccessToken(final String accessToken) throws IllegalAccessException {
        try {
            final DecodedJWT jwt = JWT.decode(accessToken);
            final Map<String, Claim> claims = jwt.getClaims();
            return claims.get("unique_name").asString();
        } catch (final Exception e2) {
            throw new IllegalArgumentException("invalid token passed");
        }
    }

    public static Date getExpirationTime(final String accessToken) {
        final DecodedJWT jwt = JWT.decode(accessToken);
        return jwt.getExpiresAt();
    }

    /**
     * This struct can probably be make private after we figure out how to integrate
     * with spring security session.
     */
    public class AccessInformation {
        String accessToken = "";
        String username = "";
        String userEmail = "";
        Date expirationTime = new Date();
    }

    private static Map<String,String> getAuthInfoFromDeploymentFile(final String callerId, final String deploymentFile) {
        final Map<String,String> settings = new HashMap<>();

        try {
            final Properties props = new Properties();
            final BufferedReader fin = new BufferedReader(new FileReader(deploymentFile);
            props.load(fin);
            for (final Entry<Object,Object> entry: props.entrySet()) {
                settings.put((String) entry.getKey(), (String) entry.getValue());
            }
        } catch (final IOException ioe) {}
        return settings;
    }

    /**
     * Save the token and info somewhere
     * @param accessJson
     */
    private String  exportAccessInfo(final String accessJson) {
        String infoFile = "/var/tmp/foo.json";
        try {
            final BufferedWriter fout = new BufferedWriter(new FileWriter(infoFile));
            fout.write(accessJson);
            fout.flush();
            fout.close();
        } catch (final IOException ioe) {
            LOG.error("Writing out final message failed", ioe);
            infoFile = "error";
        }
        return infoFile;
    }
}

