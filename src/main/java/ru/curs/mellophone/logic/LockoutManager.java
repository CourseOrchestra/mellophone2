package ru.curs.mellophone.logic;

import java.util.HashMap;

/**
 * Класс, обеспечивающий запирание на определённое время пользователя, который
 * несколько раз ввёл неверный пароль.
 */
final class LockoutManager {
	private static LockoutManager theMANAGER;
	
	/**
	 * Возвращает единственный экземпляр (синглетон) менеджера локаута пользователей.
	 */
	public static LockoutManager getLockoutManager() {
		if (theMANAGER == null) {
			theMANAGER = new LockoutManager();
		}
		return theMANAGER;
	}
	
	private static int loginAttemptsAllowed = 5;
	public static void setLoginAttemptsAllowed(int loginAttemptsAllowed) {
		LockoutManager.loginAttemptsAllowed = loginAttemptsAllowed;
	}
	
	private static long lockoutTime = 10 * 60 * 1000;
	public static void setLockoutTime(long lockoutTime) {
		LockoutManager.lockoutTime = lockoutTime * 60 * 1000;
	}
	public static long getLockoutTime() {
		return LockoutManager.lockoutTime / 60 / 1000;
	}
	

	private final HashMap<String, LoginCounter> lockouts = new HashMap<String, LoginCounter>();

	/**
	 * Счётчик состояний логина.
	 */
	private static class LoginCounter {
		private int attemptsCount = 0;
		private long lockoutUntil = 0;

		void fail() {
			attemptsCount++;
			if (attemptsCount >= loginAttemptsAllowed) {
				lockoutUntil = System.currentTimeMillis() + lockoutTime;
			}
		}

		boolean isLocked() {
			// Ещё не навводил много неверных паролей.
			if (attemptsCount < loginAttemptsAllowed)
				return false;
			// Навводил много неверных, и залочен.
			if (System.currentTimeMillis() <= lockoutUntil)
				return true;
			// Пора разлочить.
			attemptsCount = 0;
			return false;
		}
		
		int getAttemptsCount() {
			return attemptsCount;
		}
		
		long getTimeToUnlock() {
			return (lockoutUntil - System.currentTimeMillis()) / 1000;
		}
	}

	/**
	 * Вызывается для проверки, не залочен ли логин.
	 * 
	 * @param login
	 *            логин пользователя.
	 */
	public synchronized boolean isLocked(String login) {
		LoginCounter lc = lockouts.get(login);
		return lc == null ? false : lc.isLocked();
	}
	

	/**
	 * Возвращает количество неудачных попыток логина пользователя.
	 * 
	 * @param login
	 *            логин пользователя.
	 */
    public synchronized int getAttemptsCount(String login) {
		LoginCounter lc = lockouts.get(login);
		return lc == null ? 0 : lc.getAttemptsCount();
	}
	
	
	/**
	 * Возвращает время (в секундах) до разблокировки пользователя.
	 * 
	 * @param login
	 *            логин пользователя.
	 */
	public synchronized long getTimeToUnlock(String login) {
		LoginCounter lc = lockouts.get(login);
		return lc == null ? -1 : lc.getTimeToUnlock();
	}

	/**
	 * Вызвается при неверном логине пользователя.
	 * 
	 * @param login
	 *            Логин пользователя.
	 */
	public synchronized void loginFail(String login) {
		LoginCounter lc = lockouts.get(login);
		if (lc == null) {
			lc = new LoginCounter();
			lockouts.put(login, lc);
		}
		lc.fail();
	}

	/**
	 * Успешный логин амнистирует блокировку.
	 * 
	 * @param login
	 *            Логин пользователя.
	 */
	public synchronized void success(String login) {
		lockouts.remove(login);
	}
}
