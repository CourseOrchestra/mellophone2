package ru.curs.mellophone.logic;

import org.slf4j.LoggerFactory;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Конфигурация подключения к серверу ИАС БП Ространснадзора.
 * 
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
	void connect(String sesid, String login, String password, String ip,
				 ProviderContextHolder context, PrintWriter pw)
			throws EAuthServerLogic {

	}

	void disconnect(String login, String djangoauthidDisconnect) {
	}

	@Override
	void getUserInfoByName(ProviderContextHolder context, String name,
			PrintWriter pw) throws EAuthServerLogic {
	}

	@Override
	void importUsers(ProviderContextHolder context, PrintWriter pw, boolean needStartDocument)
			throws EAuthServerLogic {
	}

	@Override
	void changePwd(ProviderContextHolder context, String userName, String newpwd)
			throws EAuthServerLogic {
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
