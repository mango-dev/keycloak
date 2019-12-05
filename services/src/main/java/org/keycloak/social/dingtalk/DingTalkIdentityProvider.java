package org.keycloak.social.dingtalk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.apache.commons.codec.binary.Base64;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

import static org.keycloak.saml.processing.web.util.RedirectBindingUtil.urlEncode;

public class DingTalkIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
        implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

    public static final String AUTH_URL = "https://oapi.dingtalk.com/connect/qrconnect";
    public static final String TOKEN_URL = "https://oapi.dingtalk.com/gettoken";
    public static final String DEFAULT_SCOPE = "snsapi_login";

    public static final String API_User = "https://oapi.dingtalk.com/sns/getuserinfo_bycode";

    public static final String WECHAT_AUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize";
    public static final String WECHAT_TOKEN_URL = "https://oapi.dingtalk.com/gettoken";
    public static final String WECHAT_DEFAULT_SCOPE = "snsapi_userinfo";

    public static final String PROFILE_URL = "https://oapi.dingtalk.com/user/getUseridByUnionid?access_token=ACCESS_TOKEN&unionid=UNIONID&lang=zh_CN";

    public static final String OAUTH2_PARAMETER_CLIENT_ID = "appid";
    public static final String OAUTH2_PARAMETER_CLIENT_SECRET = "secret";

    public static final String DING_PARAMETER_CLIENT_ID = "appkey";
    public static final String DING_PARAMETER_CLIENT_SECRET = "appsecret";

    public static final String DING_APPID = "clientId2";
    public static final String DING_APPIDKEY = "clientSecret2";

    public static final String OPENID = "openid";
    public static final String WECHATFLAG = "micromessenger";

    public DingTalkIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        // TODO:log
        logger.info("1.dingtalk:开始初始化DingTalk");
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new DingTalkIdentityProvider.Endpoint(callback, realm, event);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        String uuionid = getJsonProperty(profile, "unionid");
        BrokeredIdentityContext user = new BrokeredIdentityContext(
                (uuionid != null && uuionid.length() > 0 ? uuionid : getJsonProperty(profile, "openid")));

        user.setUsername(getJsonProperty(profile, "openid"));
        user.setBrokerUserId(getJsonProperty(profile, "openid"));
        user.setModelUsername(getJsonProperty(profile, "openid"));
        user.setName(getJsonProperty(profile, "nick"));
        user.setIdpConfig(getConfig());
        user.setIdp(this);
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
        return user;
    }

    public BrokeredIdentityContext getFederatedIdentity(JsonNode response, String authorizationCode, boolean wechat) {
//        String accessToken = extractTokenFromResponse(response, getAccessTokenResponseParameter());
        String accessToken = getJsonProperty(response, getAccessTokenResponseParameter());
        if (accessToken == null) {
            throw new IdentityBrokerException("No access token available in OAuth server response: " + response);
        }
        BrokeredIdentityContext context = null;
        try {
            JsonNode profile = null;
//            if (wechat) {
//                String openid = extractTokenFromResponse(response, "openid");
//                String url = PROFILE_URL.replace("ACCESS_TOKEN", accessToken).replace("OPENID", openid);
//                profile = SimpleHttp.doGet(url, session).asJson();
//            } else {
//                profile = new ObjectMapper().readTree(response);
//            }

            logger.info("4.dingtalk:获取用户token信息");
            //获取openid信息
//            profile = getUserInfoByCode(authorizationCode).asJson();
            String profileStr = getUserInfoByCode(authorizationCode).asString();
            profileStr= new String(profileStr.getBytes("gbk"),"utf-8");
            // logger.info("4.1.dingtalk:profile=" + profileStr);
            profile=asJsonNode(profileStr);
            String errcode = getJsonProperty(profile, "errcode");
            if (errcode == "0") {
                JsonNode profile_user_info = profile.get("user_info");
                // logger.info("4.1.1.dingtalk:user_info_str="+profile_user_info.toString());

                String unionid = getJsonProperty(profile_user_info, "unionid");

                //            logger.info("4.2.dingtalk:获取用户userid信息");
                //            //获取userid信息
                //            String url = PROFILE_URL.replace("ACCESS_TOKEN", accessToken).replace("UNIONID", unionid);
                //            JsonNode userfile = SimpleHttp.doGet(url, session).asJson();
                //
                //            logger.info("4.3.dingtalk:userfile="+userfile.toString());

                context = extractIdentityFromProfile(null, profile_user_info);
            } else {
                throw new IdentityBrokerException("getUserInfoByCode.error：" + profileStr.toString());
            }
        } catch (IOException e) {
            logger.error(e);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
        return context;
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        // TODO:log
        logger.info("2.dingtalk:跳转登录");
        try {
            URI authorizationUrl = createAuthorizationUrl(request).build();
            String ua = request.getHttpRequest().getHttpHeaders().getHeaderString("user-agent").toLowerCase();
            if (isWechatBrowser(ua)) {
                return Response.seeOther(URI.create(authorizationUrl.toString() + "#wechat_redirect")).build();
            }
            return Response.seeOther(authorizationUrl).build();
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not create authentication request.", e);
        }
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    /**
     * 判断是否在微信浏览器里面请求
     *
     * @param ua 浏览器user-agent
     * @return
     */
    private boolean isWechatBrowser(String ua) {
        String dingAppId = getConfig().getConfig().get(DING_APPID);
        String dingSecret = getConfig().getConfig().get(DING_APPIDKEY);
        if (ua.indexOf(WECHATFLAG) > 0 && dingAppId != null && dingSecret != null
                && dingAppId.length() > 0 && dingSecret.length() > 0) {
            return true;
        }
        return false;
    }


    //获取openid
    public SimpleHttp getUserInfoByCode(String authorizationCode) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        String timestamp = String.valueOf(System.currentTimeMillis());
        String url=String.format("%s?accessKey=%s&timestamp=%s&signature=%s",API_User,getConfig().getClientId(),timestamp,SHA256(timestamp));
        // logger.info("4.0.2.dingtalk:getUserInfoByCode=>"+url);
        Map params = new HashMap<String, String>();
        params.put("tmp_auth_code", authorizationCode);
        return SimpleHttp.doPost(url, session).json(params);
                // .param("accessKey", getConfig().getClientId())
                // .param("timestamp", timestamp)
                // .param("signature", SHA256(timestamp));
    }
    private String SHA256(String timestamp) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        // 根据timestamp, appSecret计算签名值
        String stringToSign = timestamp;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(getConfig().getClientSecret().getBytes("UTF-8"), "HmacSHA256"));
        byte[] signatureBytes = mac.doFinal(stringToSign.getBytes("UTF-8"));
        String signature = new String(Base64.encodeBase64(signatureBytes));
        String urlEncodeSignature = urlEncode(signature);
        // logger.info("4.0.1.dingtalk:构造signature=>"+"ClientSecret:"+getConfig().getClientSecret()+",timestamp:"+timestamp+",signature:"+signature+",signature:"+urlEncodeSignature);
        return urlEncodeSignature;
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        // TODO:log
        logger.info("2.1.dingtalk:构造请求CODE的url");
        final UriBuilder uriBuilder;
        String ua = request.getHttpRequest().getHttpHeaders().getHeaderString("user-agent").toLowerCase();
        if (isWechatBrowser(ua)) {// 是微信浏览器
            logger.info("----------wechat");
            uriBuilder = UriBuilder.fromUri(WECHAT_AUTH_URL);
            uriBuilder.queryParam(OAUTH2_PARAMETER_SCOPE, WECHAT_DEFAULT_SCOPE)
                    .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                    .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
                    .queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getConfig().get(DING_APPID))
                    .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());
        } else {
            //https://oapi.dingtalk.com/connect/qrconnect?appid=APPID&response_type=code&scope=snsapi_login&state=STATE&redirect_uri=REDIRECT_URI
            uriBuilder = UriBuilder.fromUri(getConfig().getAuthorizationUrl());
            uriBuilder.queryParam(OAUTH2_PARAMETER_SCOPE, getConfig().getDefaultScope())
                    .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                    .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
                    .queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
                    .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());
        }

        String loginHint = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        if (getConfig().isLoginHint() && loginHint != null) {
            uriBuilder.queryParam(OIDCLoginProtocol.LOGIN_HINT_PARAM, loginHint);
        }

        String prompt = getConfig().getPrompt();
        if (prompt == null || prompt.isEmpty()) {
            prompt = request.getAuthenticationSession().getClientNote(OAuth2Constants.PROMPT);
        }
        if (prompt != null) {
            uriBuilder.queryParam(OAuth2Constants.PROMPT, prompt);
        }

        String nonce = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.NONCE_PARAM);
        if (nonce == null || nonce.isEmpty()) {
            nonce = UUID.randomUUID().toString();
            request.getAuthenticationSession().setClientNote(OIDCLoginProtocol.NONCE_PARAM, nonce);
        }
        uriBuilder.queryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);

        String acr = request.getAuthenticationSession().getClientNote(OAuth2Constants.ACR_VALUES);
        if (acr != null) {
            uriBuilder.queryParam(OAuth2Constants.ACR_VALUES, acr);
        }
        return uriBuilder;
    }

    protected class Endpoint {
        protected AuthenticationCallback callback;
        protected RealmModel realm;
        protected EventBuilder event;

        @Context
        protected KeycloakSession session;

        @Context
        protected ClientConnection clientConnection;

        @Context
        protected HttpHeaders headers;

        @Context
        protected UriInfo uriInfo;

        public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            this.callback = callback;
            this.realm = realm;
            this.event = event;
        }

        @GET
        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                                     @QueryParam(OAuth2Constants.ERROR) String error) {
            // TODO:log
            logger.info("3.dingtalk:获取code回调");
            logger.info("OAUTH2_PARAMETER_CODE=" + authorizationCode);
            boolean wechatFlag = false;
            if (headers != null && isWechatBrowser(headers.getHeaderString("user-agent").toLowerCase())) {
                logger.info("user-agent=wechat");
                wechatFlag = true;
            }
            if (error != null) {
                // logger.error("Failed " + getConfig().getAlias() + " broker
                // login: " + error);
                if (error.equals(ACCESS_DENIED)) {
                    logger.error(ACCESS_DENIED + " for broker login " + getConfig().getProviderId());
                    return callback.cancelled(state);
                } else {
                    logger.error(error + " for broker login " + getConfig().getProviderId());
                    return callback.error(state, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                }
            }

            try {
                BrokeredIdentityContext federatedIdentity = null;
                if (authorizationCode != null) {
                    logger.info("3.1.dingtalk:根据code获取UserInfo");
                    JsonNode response = generateTokenRequest(authorizationCode, wechatFlag).asJson();
                    logger.info("3.2.dingtalk:获取dingID的token");
                    logger.info("response=" + response);
                    //根据code,access_token获取用户的openid及userid
                    federatedIdentity = getFederatedIdentity(response, authorizationCode, wechatFlag);

                    if (getConfig().isStoreToken()) {
                        if (federatedIdentity.getToken() == null)
                            federatedIdentity.setToken(response.toString());
                    }

                    federatedIdentity.setIdpConfig(getConfig());
                    federatedIdentity.setIdp(DingTalkIdentityProvider.this);
                    federatedIdentity.setCode(state);

                    return callback.authenticated(federatedIdentity);
                }
            } catch (WebApplicationException e) {
                return e.getResponse();
            } catch (Exception e) {
                logger.error("Failed to make identity provider oauth callback", e);
            }
            event.event(EventType.LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY,
                    Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }

        public SimpleHttp generateTokenRequest(String authorizationCode) {
            return SimpleHttp.doPost(getConfig().getTokenUrl(), session).param(OAUTH2_PARAMETER_CODE, authorizationCode)
                    .param(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
                    .param(OAUTH2_PARAMETER_CLIENT_SECRET, getConfig().getClientSecret())
                    .param(OAUTH2_PARAMETER_REDIRECT_URI, uriInfo.getAbsolutePath().toString())
                    .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
        }

        //获取access_token
        public SimpleHttp generateTokenRequest(String authorizationCode, boolean wechat) {
            if (wechat) {
                return SimpleHttp.doPost(WECHAT_TOKEN_URL, session)
                        .param(OAUTH2_PARAMETER_CODE, authorizationCode)
                        .param(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getConfig().get(DING_APPID))
                        .param(OAUTH2_PARAMETER_CLIENT_SECRET, getConfig().getConfig().get(DING_APPIDKEY))
                        .param(OAUTH2_PARAMETER_REDIRECT_URI, uriInfo.getAbsolutePath().toString())
                        .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
            }
            // 获取ding_appid的access_token
            //https://oapi.dingtalk.com/gettoken?appkey=appkey&appsecret=appsecret
            //String url = "%s?%s=%s&%s=%s";
            String url = String.format("%s?%s=%s&%s=%s", getConfig().getTokenUrl(),
                    DING_PARAMETER_CLIENT_ID, getConfig().getConfig().get(DING_APPID),
                    DING_PARAMETER_CLIENT_SECRET, getConfig().getConfig().get(DING_APPIDKEY)
            );
            return SimpleHttp.doGet(url, session);
//            return SimpleHttp.doPost(getConfig().getTokenUrl(), session).param(OAUTH2_PARAMETER_CODE, authorizationCode)
//                    .param(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
//                    .param(OAUTH2_PARAMETER_CLIENT_SECRET, getConfig().getClientSecret())
//                    .param(OAUTH2_PARAMETER_REDIRECT_URI, uriInfo.getAbsolutePath().toString())
//                    .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
        }

    }
}
