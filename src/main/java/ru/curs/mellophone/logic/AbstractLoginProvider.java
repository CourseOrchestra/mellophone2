package ru.curs.mellophone.logic;

import org.slf4j.Logger;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.io.PrintWriter;
import java.util.ArrayList;

/**
 * Базовый класс провайдера логинов. Возможные наследники: LDAP-сервер,
 * XML-файл.
 */
abstract class AbstractLoginProvider {

	protected static final String AUTH_SERVER_NAMESPACE = "http://www.curs.ru/ns/AuthServer";

	protected static final String BAD_CREDENTIALS = "Неправильная пара логин/пароль";

	private static final int F0 = 0xF0;

	private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

	/**
	 * Logger.
	 */
	private Logger logger = null;

	private String url;
	
	private String type;

	private String groupProviders = "";
	
	private String id = "";
	
	private ArrayList<String> trustedUsers = null;

	static void writeXMLAttr(XMLStreamWriter xw, String attrName, String value)
			throws XMLStreamException {
		if (value != null)
			xw.writeAttribute(attrName, value);
	}

	static String asHex(byte[] buf) {
		char[] chars = new char[2 * buf.length];
		for (int i = 0; i < buf.length; ++i) {
			chars[2 * i] = HEX_CHARS[(buf[i] & F0) >>> 4];
			chars[2 * i + 1] = HEX_CHARS[buf[i] & 0x0F];
		}
		return new String(chars);
	}

	/**
	 * Инициализирует Logger для логирования данного провайдера.
	 */
	abstract void setupLogger(boolean isLogging);

	/**
	 * Устанавливает Logger.
	 */
	void setLogger(Logger logger) {
		this.logger = logger;
	}

	/**
	 * Возвращает Logger.
	 */
	Logger getLogger() {
		return logger;
	}

	/**
	 * Устанавливает строку подключения к провайдеру логинов. Это может быть
	 * адрес LDAP-сервера или путь к XML-файлу.
	 */
	void setConnectionUrl(String url) {
		this.url = url;
	}

	/**
	 * Возвращает строку подключения к провайдеру логинов. Это может быть адрес
	 * LDAP-сервера или путь к XML-файлу.
	 */
	String getConnectionUrl() {
		return url;
	}

	abstract void addReturningAttributes(String name, String value);

	/**
	 * Устанавливает соединение с провайдером логинов.
	 * 
	 * @param sesid
	 *            Идентификатор сессии приложения.
	 * @param login
	 *            Сообщеннный пользователем логин.
	 * @param password
	 *            Сообщенный пользователем пароль.
	 * @param context
	 *            Возвращаемый контекст соединения.
	 * @param pw
	 *            куда выводить информацию о пользователе
	 * @throws EAuthServerLogic
	 *             в случае, если соединение не удалось.
	 */
	abstract void connect(String sesid, String login, String password, String ip,
			ProviderContextHolder context, PrintWriter pw)
			throws EAuthServerLogic;

	/**
	 * Возвращает информацию о пользователе по имени пользователя.
	 * 
	 * @param context
	 *            Контекст соединения с провайдером логинов.
	 * @param name
	 *            имя пользователя
	 * @param pw
	 *            куда выводить информацию о пользователе
	 * @throws EAuthServerLogic
	 *             в случае, если получить информацию не удалось
	 */
	abstract void getUserInfoByName(ProviderContextHolder context, String name,
			PrintWriter pw) throws EAuthServerLogic;

	/**
	 * Осуществляет импорт пользователей.
	 * 
	 * @param context
	 *            Контекст соединения с провайдером.
	 * @param pw
	 *            куда выводить информацию.
	 * @throws EAuthServerLogic
	 *             в случае, если операция не удалась.
	 */
	abstract void importUsers(ProviderContextHolder context, PrintWriter pw, boolean needStartDocument)
			throws EAuthServerLogic;

	/**
	 * Осуществляет сброс / установку нового пароля пользователя.
	 * 
	 * @param context
	 *            Контекст соединения с провайдером.
	 * @param userName
	 *            Имя пользователя.
	 * @param newpwd
	 *            Новый пароль пользователя.
	 * @throws EAuthServerLogic
	 *             в случае, если операция не удалась.
	 */
	abstract void changePwd(ProviderContextHolder context, String userName,
			String newpwd) throws EAuthServerLogic;

	/**
	 * Создаёт контекст соединения с провайдером.
	 */
	abstract ProviderContextHolder newContextHolder();

	/**
	 * Устанавливает группу, к которой относится данный провайдер.
	 * 
	 * @param value
	 */
	public void setGroupProviders(String value) {
		groupProviders = value;
	}

	/**
	 * Возвращает группу, к которой относится данный провайдер.
	 */
	public String getGroupProviders() {
		return groupProviders;
	}

	public String getType() {
		return type;
	}

	public void setType(String aType) {
		type = aType;
	}

	public String getId() {
		return id;
	}

	public void setId(String aId) {
		id = aId;
	}

	public ArrayList<String> getTrustedUsers() {
		return trustedUsers;
	}

	public void setTrustedUsers(ArrayList<String> aTrustedUsers) {
		trustedUsers = aTrustedUsers;
	}

}

/**
 * Класс-хранитель контекста соединения с провайдером логинов.
 * 
 */
abstract class ProviderContextHolder {
	/**
	 * Финализирует контекст соединения. Данный метод вызывается всякий раз
	 * после использования контекста.
	 */
	abstract void closeContext();
}
