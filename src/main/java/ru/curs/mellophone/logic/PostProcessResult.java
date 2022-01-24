package ru.curs.mellophone.logic;

/**
 * Класс для результата выполнения ф-ции постобработки.
 * 
 */
public class PostProcessResult {
	
	private boolean success = false;
	private String message = null;
	
	public PostProcessResult() {
		super();
	}

	public PostProcessResult(final boolean aSuccess, final String aMessage) {
		super();
		success = aSuccess;
		message = aMessage;
	}

	public boolean isSuccess() {
		return success;
	}

	public void setSuccess(boolean aSuccess) {
		success = aSuccess;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String aMessage) {
		message = aMessage;
	}


}
