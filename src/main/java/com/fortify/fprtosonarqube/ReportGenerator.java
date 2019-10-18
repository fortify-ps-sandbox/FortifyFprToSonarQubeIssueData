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
package com.fortify.fprtosonarqube;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.List;

public class ReportGenerator {
	public static final String generateIssueReport(String fprFileName) throws IOException, InterruptedException {
		File reportFile = getReportFile();
		File outputFile = getOutputFile();
		generateIssueReport(fprFileName, reportFile, outputFile);
		return outputFile.getAbsolutePath();
	}

	private static final void generateIssueReport(String fprFileName, File reportFile, File outputFile) throws IOException, InterruptedException {
		String reportGeneratorCmd = System.getProperty("reportGenerator");
		if ( reportGeneratorCmd==null ) {
			throw new IllegalArgumentException("Missing required parameter -DreportGenerator=<Fortify ReportGenerator location>");
		}
		String filterSet = System.getProperty("filterSet");
		List<String> args = Arrays.asList(
				reportGeneratorCmd
				, "-template", reportFile.getAbsolutePath()
				, "-f", outputFile.getAbsolutePath()
				, "-format", "xml"
				, "-source", fprFileName);
		if ( filterSet!=null ) {
			args.add("-filterSet");
			args.add(filterSet);
		}
		new ProcessBuilder(args).start().waitFor();
	}

	private static final File getOutputFile() throws IOException {
		File outputFile = File.createTempFile("FortifyReport", ".xml");
		outputFile.deleteOnExit();
		return outputFile;
	}

	private static final File getReportFile() throws IOException {
		File reportFile = File.createTempFile("FortifyIssueReport", ".xml");
		try (InputStream inputStream = ClassLoader
				.getSystemResourceAsStream("reportgenerator/IssueReport.xml")) {
			Files.copy(inputStream, reportFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
			return reportFile;
		}
	}

}
