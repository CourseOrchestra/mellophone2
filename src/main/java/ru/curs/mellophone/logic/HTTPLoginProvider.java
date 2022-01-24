package ru.curs.mellophone.logic;

import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.TransformerException;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamSource;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

/**
 * Конфигурация подключения к HTTP-серверу.
 * 
 */
final class HTTPLoginProvider extends AbstractLoginProvider {

	private String validateUser;
	private String userInfoByName;
	private String userInfoById;

	private boolean result;

	private enum UserInfoType {
		BY_NAME, BY_ID
	}

	@Override
	void setupLogger(boolean isLogging) {
		if (isLogging) {
			setLogger(LoggerFactory.getLogger(HTTPLoginProvider.class));
		}
	}

	void setValidateUser(String validateUser) {
		this.validateUser = validateUser;
	}

	void setUserInfoByName(String userInfoByName) {
		this.userInfoByName = userInfoByName;
	}

	void setUserInfoById(String userInfoById) {
		this.userInfoById = userInfoById;
	}

	private String getAdjustUrl(String url) {
		if (!"/".equals(url.substring(url.length() - 1))) {
			url = url + "/";
		}
		return url;
	}

	private String getValidateUserUrl() {
		return getAdjustUrl(getConnectionUrl()) + validateUser;
	}

	private String getUserInfoByNameUrl() {
		return getAdjustUrl(getConnectionUrl()) + userInfoByName;
	}

	private String getUserInfoByIdUrl() {
		return getAdjustUrl(getConnectionUrl()) + userInfoById;
	}

	@Override
	void connect(String sesid, String login, String password, String ip,
			ProviderContextHolder context, PrintWriter pw)
			throws EAuthServerLogic {

		if (getLogger() != null) {
			getLogger().debug("ValidateUserUrl='" + getValidateUserUrl() + "'");
			getLogger().debug("login='" + login + "'");
		}

		HttpURLConnection c = null;
		try {
			boolean success = false;
			String message = "";
			try {
				URL server = new URL(getValidateUserUrl());
				c = (HttpURLConnection) server.openConnection();
				c.setRequestMethod("POST");
				c.setRequestProperty("Content-Type", "text/xml");
				// String urlParameters =
				// "<login name=\"User\" password=\"@User\" xmlns=\"http://www.curs.ru/ns/AuthServer\"/>";
				// c.setRequestProperty("Content-Length",
				// "" + Integer.toString(urlParameters.getBytes().length));

				c.setUseCaches(false);
				c.setDoInput(true);
				c.setDoOutput(true);

				XMLStreamWriter xw = XMLOutputFactory.newInstance()
						.createXMLStreamWriter(c.getOutputStream(), "UTF-8");
				xw.writeEmptyElement("login");
				xw.writeAttribute("name", login);
				xw.writeAttribute("password", password);
				xw.writeDefaultNamespace(AUTH_SERVER_NAMESPACE);
				xw.writeEndDocument();
				xw.flush();
				xw.close();

				c.connect();

				int responseCode = c.getResponseCode();
				String responseMessage = c.getResponseMessage();
				String errorStream = TextUtils.streamToString(c
						.getErrorStream());
				String inputStream = "";
				StreamConvertor sc = null;
				if (responseCode == HttpURLConnection.HTTP_OK) {
					sc = new StreamConvertor(c.getInputStream());
					inputStream = TextUtils.streamToString(sc.getCopy());
				}

				if (getLogger() != null) {
					getLogger().debug("responseCode='" + responseCode + "'");
					getLogger().debug(
							"responseMessage='" + responseMessage + "'");
					getLogger().debug("errorStream='" + errorStream + "'");
					getLogger().debug("inputStream='" + inputStream + "'");
				}

				if (responseCode == HttpURLConnection.HTTP_OK) {
					if (getConnectResult(sc.getCopy())) {
						success = true;
						message = "Логин пользователя '" + login + "' в '"
								+ getValidateUserUrl() + "' успешен!";
					} else {
						message = "Логин пользователя '" + login + "' в '"
								+ getValidateUserUrl() + "' не успешен: "
								+ BAD_CREDENTIALS;
					}
				} else {
					message = "Ошибка при отправке запроса '"
							+ getValidateUserUrl() + "': " + responseCode + "("
							+ responseMessage + ")" + " " + errorStream;
				}
			} catch (Exception e) {
				if (getLogger() != null) {
					getLogger().error(
							"Ошибка при отправке запроса '"
									+ getValidateUserUrl() + "': "
									+ e.getMessage());
				}

				throw EAuthServerLogic.create(e);
			}

			if (getLogger() != null) {
				getLogger().debug(message);
			}

			if (!success) {
				throw EAuthServerLogic.create(message);
			}

		} finally {
			if (c != null) {
				c.disconnect();
			}
		}
	}

	private boolean getConnectResult(InputStream is)
			throws TransformerException {
		final ContentHandler ch = new DefaultHandler() {
			@Override
			public void startElement(String uri, String localName,
					String prefixedName, Attributes atts) throws SAXException {
				if ((AUTH_SERVER_NAMESPACE.equalsIgnoreCase(uri))
						&& ("validate".equalsIgnoreCase(localName))) {
					if ("true".equalsIgnoreCase(atts.getValue("result"))) {
						result = true;
					}
				}
			}
		};
		result = false;
		SaxonTransformerFactory.newInstance().newTransformer()
				.transform(new StreamSource(is), new SAXResult(ch));
		return result;
	}

	@Override
	void getUserInfoByName(ProviderContextHolder context, String name,
			PrintWriter pw) throws EAuthServerLogic {

		UserInfoType uit;
		if (isGUID(name)) {
			uit = UserInfoType.BY_ID;
		} else {
			uit = UserInfoType.BY_NAME;
		}

		getUserInfo(uit, context, name, pw);

	}

	private boolean isGUID(String str) {
		boolean res = false;
		try {
			java.util.UUID.fromString(str);
			res = true;
		} catch (Exception e) {
		}
		return res;
	}

	private void getUserInfo(UserInfoType uit, ProviderContextHolder context,
			String name, PrintWriter pw) throws EAuthServerLogic {

		HttpURLConnection c = null;
		try {
			String userInfoUrl = "";
			String message = "";
			try {

				if (uit == UserInfoType.BY_ID) {
					userInfoUrl = getUserInfoByIdUrl();
				} else {
					userInfoUrl = getUserInfoByNameUrl();
				}
				userInfoUrl = String.format(userInfoUrl,
						URLEncoder.encode(name, "UTF-8"));

				if (getLogger() != null) {
					getLogger().debug("userInfoUrl='" + userInfoUrl + "'");
				}

				URL server = new URL(userInfoUrl);
				c = (HttpURLConnection) server.openConnection();
				c.setRequestMethod("GET");
				c.setRequestProperty("Content-Type",
						"application/x-www-form-urlencoded");

				c.setUseCaches(false);
				c.setDoInput(true);

				c.connect();

				int responseCode = c.getResponseCode();
				String responseMessage = c.getResponseMessage();
				String errorStream = TextUtils.streamToString(c
						.getErrorStream());
				String inputStream = "";
				StreamConvertor sc = null;
				if (responseCode == HttpURLConnection.HTTP_OK) {
					sc = new StreamConvertor(c.getInputStream());
					inputStream = TextUtils.streamToString(sc.getCopy());
				}

				if (getLogger() != null) {
					getLogger().debug("responseCode='" + responseCode + "'");
					getLogger().debug(
							"responseMessage='" + responseMessage + "'");
					getLogger().debug("errorStream='" + errorStream + "'");
					getLogger().debug("inputStream='" + inputStream + "'");
				}

				if (responseCode == HttpURLConnection.HTTP_OK) {
					if (isUserExists(sc.getCopy())) {
						pw.print(inputStream);
						message = "Пользователь '" + name + "' найден";
					} else {
						message = "Пользователь '" + name + "' не найден";
					}
				} else {
					message = "Ошибка при отправке запроса '" + userInfoUrl
							+ "': " + responseCode + "(" + responseMessage
							+ ")" + " " + errorStream;
				}
			} catch (Exception e) {
				message = "Ошибка при отправке запроса '" + userInfoUrl + "': "
						+ e.getMessage();
			}

			if (getLogger() != null) {
				getLogger().debug(message);
			}

		} finally {
			if (c != null) {
				c.disconnect();
			}
		}
	}

	private boolean isUserExists(InputStream is) throws TransformerException {
		final ContentHandler ch = new DefaultHandler() {
			@Override
			public void startElement(String uri, String localName,
					String prefixedName, Attributes atts) throws SAXException {
				if ((AUTH_SERVER_NAMESPACE.equalsIgnoreCase(uri))
						&& ("user".equalsIgnoreCase(localName))) {
					if (atts.getValue("login") != null) {
						result = true;
					}
				}
			}
		};
		result = false;
		SaxonTransformerFactory.newInstance().newTransformer()
				.transform(new StreamSource(is), new SAXResult(ch));
		return result;
	}

	@Override
	void importUsers(ProviderContextHolder context, PrintWriter pw, boolean needStartDocument)
			throws EAuthServerLogic {
		// TODO Auto-generated method stub
	}

	@Override
	void changePwd(ProviderContextHolder context, String userName, String newpwd)
			throws EAuthServerLogic {
		// TODO Auto-generated method stub
	}

	@Override
	void addReturningAttributes(String name, String value) {
		// TODO Auto-generated method stub

	}

	@Override
	ProviderContextHolder newContextHolder() {
		return new HTTPLink();
	}

	/**
	 * Контекст соединения с HTTP-сервером (пустышка).
	 */
	private static class HTTPLink extends ProviderContextHolder {
		@Override
		void closeContext() {
		}
	}

}
