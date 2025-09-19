package org.forrest.keycloak.http;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import okhttp3.logging.HttpLoggingInterceptor;
import org.forrest.keycloak.bind.RemoteCredentialInput;
import org.forrest.keycloak.bind.RemoteUserEntity;
import org.forrest.keycloak.bind.UserCountResponse;
import org.forrest.keycloak.bind.VerifyPasswordResponse;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import java.io.IOException;
import java.util.*;

import static org.forrest.keycloak.bind.RemoteUserStorageProviderConstants.*;

public class UserService {
    private static final Logger logger = Logger.getLogger(UserService.class);
    private final String UA = "Keycloak User Federation SPI";
    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private final OkHttpClient httpClient;
    private final String findUserUrl;
    private final String verifyUserUrl;
    private final String searchUserUrl;
    private final String countUserUrl;
    private final String authorization;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public UserService(KeycloakSession session, ComponentModel model, boolean debugLoggingEnabled) {
        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder()
            .addInterceptor(new HeaderForwardingInterceptor(session, model));

        if (debugLoggingEnabled) {
            // Create HTTP logging interceptor using JBoss Logger
            HttpLoggingInterceptor logging = new HttpLoggingInterceptor(message -> {
                logger.infof("[HTTP] %s", message);
            });
            logging.setLevel(HttpLoggingInterceptor.Level.BODY);
            clientBuilder.addInterceptor(logging);
        }

        this.httpClient = clientBuilder.build();
        this.findUserUrl = model.get(REMOTE_PROVIDER_URL) + model.get(FIND_USER_ENDPOINT);
        this.verifyUserUrl = model.get(REMOTE_PROVIDER_URL) + model.get(VERIFY_USER_ENDPOINT);
        this.searchUserUrl = model.get(REMOTE_PROVIDER_URL) + model.get(SEARCH_USER_ENDPOINT);
        this.countUserUrl = model.get(REMOTE_PROVIDER_URL) + model.get(COUNT_USER_ENDPOINT);
        this.authorization = model.get(AUTHORIZATION);
    }

    public List<RemoteUserEntity> searchUsers(Map<String, String> params, Integer firstResult, Integer maxResults) throws IOException {
        if (firstResult != null) {
            params.put("skip", String.valueOf(firstResult));
        }
        if (maxResults != null) {
            params.put("take", String.valueOf(maxResults));
        }
        try (Response response = doQuery(searchUserUrl, params)) {
            if (response.body() == null) {
                return null;
            }
            return objectMapper.readValue(response.body().charStream(), new TypeReference<List<RemoteUserEntity>>() {
            });
        }
    }

    public RemoteUserEntity getUser(Map<String, String> params) {
        try (Response response = doQuery(findUserUrl, params)) {
            if (response.body() == null) {
                return null;
            }
            return objectMapper.readValue(response.body().charStream(), RemoteUserEntity.class);
        } catch (Exception e) {
            return null;
        }
    }

    public RemoteUserEntity getUserById(String id) {
        Map<String, String> params = new HashMap<>() {{
            put("type", "id");
            put("id", id);
        }};
        return getUser(params);
    }

    public RemoteUserEntity getUserByUsername(String username) {
        Map<String, String> params = new HashMap<>() {{
            put("type", "username");
            put("username", username);
        }};
        return getUser(params);
    }

    public RemoteUserEntity getUserByEmail(String email) {
        Map<String, String> params = new HashMap<>() {{
            put("type", "email");
            put("email", email);
        }};
        return getUser(params);
    }

    public UserCountResponse getUserCount(Map<String, String> params) {
        try (Response response = doQuery(countUserUrl, params)) {
            if (response.body() == null) {
                return new UserCountResponse(0);
            }
            return objectMapper.readValue(response.body().charStream(), UserCountResponse.class);
        } catch (Exception e) {
            return new UserCountResponse(0);
        }
    }

    public VerifyPasswordResponse verifyPassword(String username, String password) throws IOException {
        RequestBody formBody = RequestBody.create(objectMapper.writeValueAsString(new RemoteCredentialInput(username, password)), JSON);
        okhttp3.Request.Builder builder = buildRequest()
            .url(verifyUserUrl);
        
        Request request = builder.post(formBody).build();
        Response response = httpClient.newCall(request).execute();
        if (response.body() == null) {
            return new VerifyPasswordResponse(false);
        }

        return objectMapper.readValue(response.body().charStream(), VerifyPasswordResponse.class);
    }

    private Response doQuery(String url, Map<String, String> params) throws IOException {
        HttpUrl.Builder httpBuilder = Objects.requireNonNull(HttpUrl.parse(url)).newBuilder();
        for (Map.Entry<String, String> param : params.entrySet()) {
            httpBuilder.addQueryParameter(param.getKey(), param.getValue());
        }

        Request.Builder request = buildRequest().url(httpBuilder.build());
        return httpClient.newCall(request.build()).execute();
    }

    private okhttp3.Request.Builder buildRequest() {
        var builder = new Request.Builder()
            .addHeader("User-Agent", UA);

        if (!"".equals(authorization) && authorization != null)
            builder.addHeader("Authorization", authorization);

        return builder;
    }
}
