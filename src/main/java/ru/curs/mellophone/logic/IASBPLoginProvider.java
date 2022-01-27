package ru.curs.mellophone.logic;

import org.apache.commons.text.StringEscapeUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.slf4j.LoggerFactory;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Конфигурация подключения к серверу ИАС БП Ространснадзора.
 */
final class IASBPLoginProvider extends AbstractLoginProvider {

    private static final int HTTP_OK = 200;

    private String djangoauthid = null;

    public String getDjangoauthid() {
        return djangoauthid;
    }

    @Override
    void setupLogger(boolean isLogging) {
        if (isLogging) {
            setLogger(LoggerFactory.getLogger(IASBPLoginProvider.class));
        }
    }

    private String getAdjustUrl(String url) {
        if (!"/".equals(url.substring(url.length() - 1))) {
            url = url + "/";
        }
        return url;
    }

    private String getLoginUrl() {
        return getAdjustUrl(getConnectionUrl()) + "mellophonelogin";
    }

    private String getLogoutUrl() {
        return getAdjustUrl(getConnectionUrl()) + "mellophonelogout";
    }

    @Override
    void connect(String sesid, String login, String password, String ip, ProviderContextHolder context, PrintWriter pw) throws EAuthServerLogic {

        if (getLogger() != null) {
            getLogger().debug("LoginUrl='" + getLoginUrl() + "'");
            getLogger().debug("login='" + login + "'");
        }

        boolean success = false;
        String message = "";

        CloseableHttpClient httpclient = HttpClientBuilder.create().build();
        try {
            HttpPost httppost = new HttpPost(getLoginUrl());

            httppost.setHeader("Content-Type", "application/json; charset=utf-8");

            httppost.setEntity(new StringEntity(String.format("username=%s&password=%s", login, password)));

            HttpResponse response = httpclient.execute(httppost);

            HttpEntity resEntity = response.getEntity();

            if (resEntity != null) {
                String resContent = EntityUtils.toString(resEntity);
                if (response.getStatusLine().getStatusCode() == HTTP_OK) {
                    JSONTokener jt = new JSONTokener(resContent);
                    JSONObject jo = new JSONObject(jt);

                    djangoauthid = jo.getString("django_auth_id");

                    try {
                        XMLStreamWriter xw = XMLOutputFactory.newInstance().createXMLStreamWriter(pw);
                        xw.writeStartDocument("utf-8", "1.0");
                        xw.writeEmptyElement("user");
                        xw.writeAttribute("login", jo.getString("l"));
                        xw.writeAttribute("name", jo.getString("name"));
                        xw.writeAttribute("SID", String.valueOf(jo.getLong("sid")));
                        xw.writeEndDocument();
                        xw.flush();

                        success = true;
                    } catch (XMLStreamException e) {
                        message = "Ошибка при формировании xml-данных пользователя: " + e.getMessage();
                    }
                } else {
                    message = resContent;

                    message = StringEscapeUtils.unescapeJava(message);
                }
            } else {
                message = "HTTP-запрос проверки пользователя в ИАС БП вернул пустые данные.";
            }

            EntityUtils.consume(resEntity);

        } catch (Exception e) {
            message = e.getMessage();
        } finally {
            try {
                httpclient.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        if (getLogger() != null) {
            if (success) {
                getLogger().debug("Логин пользователя '" + login + "' в '" + getLoginUrl() + "' успешен!");
            } else {
                getLogger().debug("Логин пользователя '" + login + "' в '" + getLoginUrl() + "' не успешен по причине: " + message);
            }
        }

        if (!success) {
            throw EAuthServerLogic.create(message);
        }

    }

    void disconnect(String login, String djangoauthidDisconnect) {

        if (getLogger() != null) {
            getLogger().debug("LogoutUrl='" + getLogoutUrl() + "'");
        }

        boolean success = false;
        String message = "";

        CloseableHttpClient httpclient = HttpClientBuilder.create().build();
        try {
            HttpPost httppost = new HttpPost(getLogoutUrl());

            httppost.setHeader("Content-Type", "application/json; charset=utf-8");

            httppost.setEntity(new StringEntity(String.format("django_auth_id=%s", djangoauthidDisconnect)));

            HttpResponse response = httpclient.execute(httppost);

            HttpEntity resEntity = response.getEntity();

            if (resEntity != null) {
                String resContent = EntityUtils.toString(resEntity);
                if (response.getStatusLine().getStatusCode() == HTTP_OK) {
                    success = true;
                } else {
                    message = resContent;

                    message = StringEscapeUtils.unescapeJava(message);
                }
            } else {
                message = "HTTP-запрос логаута пользователя в ИАС БП вернул пустые данные.";
            }

            EntityUtils.consume(resEntity);

        } catch (Exception e) {
            message = e.getMessage();
        } finally {
            try {
                httpclient.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        if (getLogger() != null) {
            if (success) {
                getLogger().debug("Логаут пользователя '" + login + "' из '" + getLogoutUrl() + "' успешен!");
            } else {
                getLogger().debug("Логаут пользователя '" + login + "' из '" + getLogoutUrl() + "' не успешен по причине: " + message);
            }
        }

    }

    @Override
    void getUserInfoByName(ProviderContextHolder context, String name, PrintWriter pw) throws EAuthServerLogic {
    }

    @Override
    void importUsers(ProviderContextHolder context, PrintWriter pw, boolean needStartDocument) throws EAuthServerLogic {
    }

    @Override
    void changePwd(ProviderContextHolder context, String userName, String newpwd) throws EAuthServerLogic {
    }

    @Override
    void addReturningAttributes(String name, String value) {
    }

    @Override
    ProviderContextHolder newContextHolder() {
        return new IASBPLink();
    }

    /**
     * Контекст соединения с IASBP-сервером (пустышка).
     */
    private static class IASBPLink extends ProviderContextHolder {
        @Override
        void closeContext() {
        }
    }

}
