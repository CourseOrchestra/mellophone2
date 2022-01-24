package ru.curs.mellophone.logic;

import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamSource;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Конфигурация подключения к XML-файлу.
 * 
 */
public final class XMLLoginProvider extends AbstractLoginProvider {

	private static final String LOGIN = "login";
	private static final String USER = "user";
	private static final String ERROR_PARSE_FILE = "Ошибка разбора файла '%s': %s";

	private static final MessageDigest MD;
	static {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			// Если такое случилось --- у нас Java неправильно стоит...
			e.printStackTrace();
			md = null;
		}
		MD = md;
	}

	@Override
	void setupLogger(boolean isLogging) {
		if (isLogging) {
			setLogger(LoggerFactory.getLogger(XMLLoginProvider.class));
		}
	}

	@Override
	void connect(String sesid, final String login, final String password, String ip,
			final ProviderContextHolder ldapLink, PrintWriter pw)
			throws EAuthServerLogic {

		ContentHandler ch = new DefaultHandler() {
			@Override
			public void startElement(String uri, String localName,
					String prefixedName, Attributes atts) throws SAXException {
				if (USER.equals(localName)) {
					String lgn = atts.getValue(LOGIN);
					String pwd = atts.getValue("password");
					try {
						if ((lgn != null)
								&& (pwd != null)
								&& lgn.equalsIgnoreCase(login)
								&& (pwd.equals(password) || pwd
										.equals(getHash(password)))) {
							try {
								((XMLLink) ldapLink).inXML = getXMLstream();
							} catch (FileNotFoundException e) {
								throw new SAXException(e);
							}
						}
					} catch (UnsupportedEncodingException e) {
						throw new SAXException(e);
					}
				}
			}
		};

		if (getLogger() != null) {
			getLogger().debug("Url='" + getConnectionUrl() + "'");
			getLogger().debug("login='" + login + "'");
		}

		try {
			((XMLLink) ldapLink).inXML = null;

			InputStream fis = getXMLstream();
			SaxonTransformerFactory.newInstance().newTransformer()
					.transform(new StreamSource(fis), new SAXResult(ch));

		} catch (Exception e) {

			if (getLogger() != null) {
				getLogger().error(
						String.format(ERROR_PARSE_FILE, getConnectionUrl(),
								e.getMessage()));
			}

			throw EAuthServerLogic.create(String.format(ERROR_PARSE_FILE,
					getConnectionUrl(), e.getMessage()));

		}

		if (((XMLLink) ldapLink).inXML == null) {

			if (getLogger() != null) {
				getLogger().error(
						"Логин пользователя '" + login + "' в '"
								+ getConnectionUrl() + "' не успешен: "
								+ BAD_CREDENTIALS);
			}

			throw EAuthServerLogic.create(BAD_CREDENTIALS);
		}

		if (getLogger() != null) {
			getLogger().debug(
					"Логин пользователя '" + login + "' в '"
							+ getConnectionUrl() + "' успешен!");
		}

	}

	private InputStream getXMLstream() throws FileNotFoundException {
		File xmlfile = new File(getConnectionUrl());
		InputStream fis;
		if (xmlfile.isAbsolute())
			fis = new FileInputStream(xmlfile);
		else {
			// чтобы можно было вносить правки в users.xml без перезагрузки
			// Томката
			fis = new FileInputStream(xmlfile);

			// ClassLoader classLoader = Thread.currentThread()
			// .getContextClassLoader();
			// fis = classLoader.getResourceAsStream(AuthManager.DIR_CONFIG
			// + getConnectionUrl());
		}
		return fis;
	}

	@Override
	void getUserInfoByName(ProviderContextHolder ldapLink, final String name,
			final PrintWriter pw) throws EAuthServerLogic {

		if (getLogger() != null) {
			getLogger().debug("Url='" + getConnectionUrl() + "'");
			getLogger().debug("name='" + name + "'");
		}

		final XMLStreamWriter xw;
		try {
			xw = XMLOutputFactory.newInstance().createXMLStreamWriter(pw);
		} catch (Exception e) {
			e.printStackTrace();
			throw EAuthServerLogic.create(e);
		}

		ContentHandler ch = new DefaultHandler() {
			@Override
			public void startElement(String uri, String localName,
					String prefixedName, Attributes atts) throws SAXException {
				if (USER.equals(localName) && name.equalsIgnoreCase(atts.getValue(LOGIN))) {
					try {
						if (getLogger() != null) {
							getLogger().debug(
									"Пользователь '" + name + "' найден");
						}

						writeUserInfo(xw, atts);
					} catch (Exception e) {
						throw new SAXException(e);
					}
				}
			}
		};

		try {
			xw.writeStartDocument("utf-8", "1.0");
			SaxonTransformerFactory
					.newInstance()
					.newTransformer()
					.transform(new StreamSource(((XMLLink) ldapLink).inXML),
							new SAXResult(ch));
			xw.writeEndDocument();
			xw.flush();
		} catch (Exception e) {

			if (getLogger() != null) {
				getLogger().error(
						String.format(ERROR_PARSE_FILE, getConnectionUrl(),
								e.getMessage()));
			}

			throw EAuthServerLogic.create(String.format(ERROR_PARSE_FILE,
					getConnectionUrl(), e.getMessage()));
		}

	}

	@Override
	void importUsers(ProviderContextHolder ldapLink, final PrintWriter pw, boolean needStartDocument)
			throws EAuthServerLogic {

		if (getLogger() != null) {
			getLogger().debug("Url='" + getConnectionUrl() + "'");
		}

		final XMLStreamWriter xw;
		try {
			xw = XMLOutputFactory.newInstance().createXMLStreamWriter(pw);
		} catch (Exception e) {
			e.printStackTrace();
			throw EAuthServerLogic.create(e);
		}

		ContentHandler ch = new DefaultHandler() {
			@Override
			public void startElement(String uri, String localName,
					String prefixedName, Attributes atts) throws SAXException {
				if (USER.equals(localName)) {
					try {
						writeUserInfo(xw, atts);
					} catch (Exception e) {
						throw new SAXException(e);
					}

				}
			}
		};

		try {
			
			if(((XMLLink) ldapLink).inXML == null){
				((XMLLink) ldapLink).inXML = getXMLstream();	
			}
			
			if(needStartDocument){
				xw.writeStartDocument("utf-8", "1.0");					
			}
			xw.writeStartElement("users");
			writeXMLAttr(xw, "pid", getId());
			SaxonTransformerFactory
					.newInstance()
					.newTransformer()
					.transform(new StreamSource(((XMLLink) ldapLink).inXML),
							new SAXResult(ch));
			xw.writeEndDocument();
			xw.flush();

			if (getLogger() != null) {
				getLogger().debug("Импорт пользователей успешно завершен");
			}

		} catch (Exception e) {

			if (getLogger() != null) {
				getLogger().error(
						String.format(ERROR_PARSE_FILE, getConnectionUrl(),
								e.getMessage()));
			}

			throw EAuthServerLogic.create(String.format(ERROR_PARSE_FILE,
					getConnectionUrl(), e.getMessage()));
		}

	}

	@Override
	void changePwd(ProviderContextHolder ldapLink, String userName,
			String newpwd) throws EAuthServerLogic {
		// TODO Auto-generated method stub

	}

	@Override
	void addReturningAttributes(String name, String value) {
		// TODO Auto-generated method stub

	}

	@Override
	ProviderContextHolder newContextHolder() {
		return new XMLLink();
	}

	/**
	 * Возвращает значение функции SHA-1 для строки символов в виде 16-ричного
	 * числа, в точности как реализовано в клиентском JavaScript. Необходимо для
	 * контроля логинов и паролей
	 * 
	 * @throws UnsupportedEncodingException
	 */
	private static String getHash(String input)
			throws UnsupportedEncodingException {
		synchronized (MD) {
			MD.reset();
			MD.update(input.getBytes("UTF-8"));
			return asHex(MD.digest());
		}
	}

	private static void writeUserInfo(XMLStreamWriter xw, Attributes atts)
			throws XMLStreamException {
		xw.writeEmptyElement(USER);

		writeXMLAttr(xw, LOGIN, atts.getValue(LOGIN));
		writeXMLAttr(xw, "SID", atts.getValue("SID"));
		writeXMLAttr(xw, "name", atts.getValue("name"));
		writeXMLAttr(xw, "email", atts.getValue("email"));
		writeXMLAttr(xw, "phone", atts.getValue("phone"));
		writeXMLAttr(xw, "organization", atts.getValue("organization"));
		writeXMLAttr(xw, "fax", atts.getValue("fax"));
	}

	/**
	 * Контекст соединения с XML-файлом.
	 */
	private static class XMLLink extends ProviderContextHolder {
		private InputStream inXML;

		@Override
		void closeContext() {
			try {
				if (inXML != null)
					inXML.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}

}
