/*******************************************************************************
 * (c) Copyright 2017 EntIT Software LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a 
 * copy of this software and associated documentation files (the 
 * "Software"), to deal in the Software without restriction, including without 
 * limitation the rights to use, copy, modify, merge, publish, distribute, 
 * sublicense, and/or sell copies of the Software, and to permit persons to 
 * whom the Software is furnished to do so, subject to the following 
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be included 
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY 
 * KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN 
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
 * IN THE SOFTWARE.
 ******************************************************************************/
package com.fortify.util.xml;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Stack;

import javax.xml.stream.StreamFilter;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.XMLEvent;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.dataformat.xml.XmlFactory;

public abstract class AbstractStreamingXmlParser<T extends AbstractStreamingXmlParser<T>> {
	private static final XMLInputFactory XML_FACTORY = _getXmlInputFactory();
	private static final StreamFilter START_OR_END_ELT_FILTER = new StreamFilter() {
		@Override
		public boolean accept(XMLStreamReader reader) {
			return reader.isStartElement() || reader.isEndElement();
		}
	};
	private final Map<String, XmlHandler> pathToHandlerMap = new LinkedHashMap<>();
	@SuppressWarnings("unchecked")
	private final T _this = (T)this;
	
	public final T handler(String path, XmlHandler handler) {
		pathToHandlerMap.put(path, handler);
		return _this;
	}

	public final void parse(InputStream inputStream) throws IOException, XMLStreamException {
		XMLStreamReader unfilteredReader = XML_FACTORY.createXMLStreamReader(inputStream);
		XMLStreamReader filteredReader = XML_FACTORY.createFilteredReader(unfilteredReader, START_OR_END_ELT_FILTER);
		parse(filteredReader, unfilteredReader, new Stack<String>());
	}

	private final void parse(XMLStreamReader filteredReader, XMLStreamReader unfilteredReader, Stack<String> stack) throws XMLStreamException, IOException {
		while (filteredReader.hasNext()) {
			int type = filteredReader.next();
			if ( type==XMLEvent.START_ELEMENT ) {
				stack.push(filteredReader.getLocalName()); 
				XmlHandler handler = pathToHandlerMap.get(String.join("/", stack));
				if ( handler != null ) {
					handler.handle(unfilteredReader);
					stack.pop();
				}
			}
			if ( filteredReader.getEventType()==XMLEvent.END_ELEMENT && stack.size()>0 && stack.lastElement().equals(filteredReader.getLocalName())) {
				stack.pop();
			}
		}
	}

	private static final XMLInputFactory _getXmlInputFactory() {
		XMLInputFactory inputFactory = XMLInputFactory.newFactory();
		inputFactory.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, false);
		inputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
		return XmlFactory.builder().disable(StreamReadFeature.AUTO_CLOSE_SOURCE).inputFactory(inputFactory).build()
				.getXMLInputFactory();
	}
}
