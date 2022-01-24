package ru.curs.mellophone.logic;

import javax.xml.transform.TransformerFactory;

/**
 * Saxon фабрика.
 * 
 * @author bogatov
 * 
 */
public final class SaxonTransformerFactory {

	private SaxonTransformerFactory() {

	}

	/**
	 * Возвращает экземпляр класса net.sf.saxon.TransformerFactoryImpl.
	 * 
	 * @return TransformerFactory
	 */
	public static TransformerFactory newInstance() {
		return new net.sf.saxon.TransformerFactoryImpl();
	}
}
