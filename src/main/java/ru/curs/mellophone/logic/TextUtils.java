package ru.curs.mellophone.logic;

import java.io.*;
import java.text.DateFormat;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Класс, содержащий общие функции для работы с текстом.
 * 
 * @author den
 * 
 */
public final class TextUtils {

	/**
	 * Кодировка по умолчанию в приложении. Все выходные и входные документы по
	 * умолчанию должны имеют данную кодировку (если явно не указано другое).
	 */
	public static final String DEF_ENCODING = "UTF-8";

	private TextUtils() {
		throw new UnsupportedOperationException();
	}

	/**
	 * Преобразует InputStream в кодировке DEF_ENCODING в строку. Может
	 * использоваться при работе с Gateway классами и\или при отладке.
	 * 
	 * @param is
	 *            - InputStream
	 * @return - строка с содержимым InputStream.
	 * @throws IOException
	 *             IOException
	 */
	public static String streamToString(final InputStream is)
			throws IOException {
		if (is != null) {
			Writer writer = new StringWriter();
			final int bufMaxLen = 4096;
			char[] buffer = new char[bufMaxLen];
			try {
				Reader reader = new BufferedReader(new InputStreamReader(is,
						DEF_ENCODING));
				int n;
				while ((n = reader.read(buffer)) != -1) {
					writer.write(buffer, 0, n);
				}
			} finally {
				is.close();
			}
			return writer.toString();
		} else {
			return "";
		}
	}

	/**
	 * Преобразует строку в InputStream. Может использоваться при работе с
	 * Gateway классами и\или при отладке.
	 * 
	 * @param str
	 *            - строка.
	 * @return - InputStream.
	 * @throws UnsupportedEncodingException
	 *             UnsupportedEncodingException
	 */
	public static InputStream stringToStream(final String str)
			throws UnsupportedEncodingException {
		return new ByteArrayInputStream(str.getBytes(DEF_ENCODING));

	}

	/**
	 * Возвращает числовое значение размера, извлеченное из переданной строки.
	 * 
	 * @param value
	 *            - строка с размером.
	 * @return - числовое значение.
	 */
	public static Integer getIntSizeValue(final String value) {
		Integer intValue = null;
		String strValue;
		if (value.indexOf("px") > -1) {
			strValue = value.substring(0, value.indexOf("px"));
			intValue = Integer.valueOf(strValue); // TODO проверить
		}
		return intValue;
	}

	/**
	 * Функция, возвращающая исходное слово, начинающееся с заглавной буквы. Все
	 * остальные буквы результата будут строчные.
	 * 
	 * @param source
	 *            - исходная строка.
	 * @return - преобразованная строка.
	 */
	public static String capitalizeWord(final String source) {
		return String.format("%s%s", source.substring(0, 1).toUpperCase(),
				source.substring(1));
	}

	/**
	 * Функция нечувствительной к реестру замены.
	 * 
	 * @param template
	 *            - шаблон для замены.
	 * @param source
	 *            - исходная строка.
	 * @param newValue
	 *            - значение для замены
	 * @return - результат после замены.
	 */
	public static String replaceCI(final String source, final String template,
			final String newValue) {
		Pattern pattern = Pattern.compile(template, Pattern.CASE_INSENSITIVE
				+ Pattern.UNICODE_CASE);
		Matcher matcher = pattern.matcher(source);
		String result = matcher.replaceAll(newValue);
		return result;
	}

	/**
	 * Перекодирует строку из неправильно определенной кодировки в правильную.
	 * 
	 * @param source
	 *            - исходный текст.
	 * @param sourceCharset
	 *            - кодировка исходного текста.
	 * @param destCharset
	 *            - правильная кодировка.
	 * @return - строка в верной кодировке.
	 * @throws UnsupportedEncodingException
	 *             UnsupportedEncodingException
	 */
	public static String recode(final String source,
			final String sourceCharset, final String destCharset)
			throws UnsupportedEncodingException {
		return new String(source.getBytes(sourceCharset), destCharset);
	}

	/**
	 * Функция, возвращающая строку с текущей датой.
	 * 
	 * @return строка с датой.
	 */
	public static String getCurrentLocalDate() {
		DateFormat df = DateFormat.getDateTimeInstance();
		return df.format(new Date());
	}

	/**
	 * Возвращает имя файла без пути и расширения.
	 * 
	 * @param path
	 *            - полный путь к файлу.
	 * @return - имя файла.
	 */
	public static String extractFileName(final String path) {
		if (path == null) {
			return null;
		}

		int dotPos = path.lastIndexOf('.');
		int slashPos = path.lastIndexOf('\\');
		if (slashPos == -1) {
			slashPos = path.lastIndexOf('/');
		}

		int beginIndex = slashPos > 0 ? slashPos + 1 : 0;
		int endIndex = dotPos > slashPos ? dotPos : path.length();

		return path.substring(beginIndex, endIndex);
	}

	/**
	 * Возвращает имя файла с расширением из полного пути.
	 * 
	 * @param path
	 *            - путь к файлу.
	 * @return - имя с расширением.
	 */
	public static String extractFileNameWithExt(final String path) {
		if (path == null) {
			return null;
		}

		File file = new File(path);
		return file.getName();
	}

}
