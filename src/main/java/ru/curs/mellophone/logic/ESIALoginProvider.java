package ru.curs.mellophone.logic;

import org.slf4j.LoggerFactory;

import java.io.PrintWriter;

/**
 * Провайдер ESIA.
 * 
 */
final class ESIALoginProvider extends AbstractLoginProvider {

	@Override
	void setupLogger(boolean isLogging) {
		if (isLogging) {
			setLogger(LoggerFactory.getLogger(ESIALoginProvider.class));
		}
	}

	@Override
	void connect(String sesid, final String login, final String password, String ip,
			final ProviderContextHolder ldapLink, PrintWriter pw)
			throws EAuthServerLogic {
	}

	@Override
	void getUserInfoByName(ProviderContextHolder ldapLink, final String name,
			final PrintWriter pw) throws EAuthServerLogic {
	}

	@Override
	void importUsers(ProviderContextHolder ldapLink, final PrintWriter pw, boolean needStartDocument)
			throws EAuthServerLogic {
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
		return new ESIALink();
	}

	/**
	 * Контекст соединения с ESIA.
	 */
	private static class ESIALink extends ProviderContextHolder {
		@Override
		void closeContext() {
		}
	}

}
