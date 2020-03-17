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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Map;

import javax.xml.stream.XMLStreamException;

import org.mapdb.DB;
import org.mapdb.DBMaker;

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;

public class FprToSonarQube {
	private final String fprFileName;
	private final String outputFileName;
	
	public FprToSonarQube(String fprFileName, String outputFileName) {
		this.fprFileName = fprFileName;
		this.outputFileName = outputFileName;
	}
	
	private void process() throws FileNotFoundException, IOException, XMLStreamException, InterruptedException {
		String reportFileName = ReportGenerator.generateIssueReport(fprFileName);
		try (JsonGenerator generator = new JsonFactory().createGenerator(
                        new File(outputFileName)
                        , JsonEncoding.UTF8);
			 DB db = DBMaker.tempFileDB()
						.closeOnJvmShutdown().fileDeleteAfterClose()
						.fileMmapEnableIfSupported()
						.make()) {
			generator.setCodec(new ObjectMapper());
			generator.setPrettyPrinter(new DefaultPrettyPrinter());
			generator.writeStartObject();
			Map<String, String> iidToFolderMap = new ReportParser(reportFileName, db).parse(generator);
			new FvdlParser(fprFileName, iidToFolderMap).parse(generator);
			generator.writeEndObject();
		}
	}

	public static void main(String[] args) throws IOException, XMLStreamException, InterruptedException {
		if (args.length != 1) {
			System.err.println("Usage: java -DreportGenerator=<Fortify ReportGenerator location> -jar FprToSonarQube.jar <file.fpr>");
			System.exit(1);
		}
		new FprToSonarQube(args[0], args[0].replace(".fpr", ".json")).process();
	}
}
