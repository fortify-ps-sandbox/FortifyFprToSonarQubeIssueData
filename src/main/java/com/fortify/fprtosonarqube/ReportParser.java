/*******************************************************************************
 * (c) Copyright 2020 Micro Focus or one of its affiliates
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
package com.fortify.fprtosonarqube;

import java.io.IOException;
import java.util.Map;

import javax.xml.stream.XMLStreamException;

import org.mapdb.DB;
import org.mapdb.Serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fortify.fprtosonarqube.domain.report.ReportIssue;
import com.fortify.util.xml.StreamingXmlParser;
import com.fortify.util.xml.XmlMapperHelper;

public class ReportParser {
	private final String reportFileName;
	private final Map<String,String> iidToFolderMap;
	
	public ReportParser(String reportFileName, DB db) {
		this.reportFileName = reportFileName;
		iidToFolderMap = db.hashMap("rules", Serializer.STRING_ASCII, Serializer.STRING_ASCII).create();
	}

	public Map<String,String> parse(final JsonGenerator generator) throws IOException, XMLStreamException {
		new StreamingXmlParser()
			.handler("ReportSection/SubSection/IssueListing/Chart/GroupingSection/Issue", reader->{
				ReportIssue issue = XmlMapperHelper.getDefaultXmlMapper().readValue(reader, ReportIssue.class);
				System.out.println(issue);
				iidToFolderMap.put(issue.getIid(), issue.getFolder());
			})
			.parse(reportFileName);
		return iidToFolderMap;
	}
}
