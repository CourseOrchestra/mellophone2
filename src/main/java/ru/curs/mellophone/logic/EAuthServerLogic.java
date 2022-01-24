package ru.curs.mellophone.logic;

/**
 * Класс исключений логики сервера аутентификации.
 * 
 */
public abstract class EAuthServerLogic extends Exception {

	private static final long serialVersionUID = -110175493360344111L;

	private BadLoginType badLoginType = BadLoginType.BAD_CREDENTIALS;

	private EAuthServerLogic(Exception e) {
		super(e);
	}

	private EAuthServerLogic() {

	}

	/**
	 * Создаёт исключение с произвольным сообщением.
	 * 
	 * @param message
	 *            сообщение
	 */
	public static EAuthServerLogic create(final String message) {
		return new EAuthServerLogic() {

			private static final long serialVersionUID = -5142944854432454830L;

			@Override
			public String getMessage() {
				return message;
			}

		};
	}

	/**
	 * Создаёт исключение EAuthServerLogic на базе другого исключения.
	 * 
	 * @param e
	 *            Исключение, породившее данное исключение.
	 * 
	 */
	public static EAuthServerLogic create(Exception e) {

		return new EAuthServerLogic(e) {
			private static final long serialVersionUID = 757009838204079513L;
		};
	}

	/**
	 * Возвращает BadLoginType.
	 */
	public BadLoginType getBadLoginType() {
		return badLoginType;
	}

	/**
	 * Устанавливает BadLoginType.
	 * 
	 * @param badLoginType
	 *            Исходный badLoginType
	 */
	public void setBadLoginType(BadLoginType badLoginType) {
		this.badLoginType = badLoginType;
	}

}
