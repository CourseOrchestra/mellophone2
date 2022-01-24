package ru.curs.mellophone.logic;

/**
 * Возможные типы неудачного логина.
 * 
 */
public enum BadLoginType {

	/**
	 * Неправильная пара логин/пароль.
	 */
	BAD_CREDENTIALS,
	/**
	 * Неуспешная проверка пользователя процедурой proccheckuser в
	 * SQLLoginProvider'e.
	 */
	BAD_PROC_CHECK_USER,
	/**
	 * Пользователь постоянно заблокирован.
	 */
	USER_BLOCKED_PERMANENTLY;	

}
