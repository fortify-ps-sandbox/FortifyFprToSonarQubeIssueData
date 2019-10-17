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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.xml.stream.XMLStreamException;

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fortify.fprtosonarqube.domain.fvdl.Description;
import com.fortify.fprtosonarqube.domain.fvdl.Vulnerability;
import com.fortify.fprtosonarqube.domain.fvdl.Vulnerability.Entry;
import com.fortify.fprtosonarqube.domain.fvdl.Vulnerability.Node;
import com.fortify.fprtosonarqube.domain.fvdl.Vulnerability.SourceLocation;
import com.fortify.fprtosonarqube.domain.sonarqube.Issue;
import com.fortify.fprtosonarqube.domain.sonarqube.Issue.Location;
import com.fortify.fprtosonarqube.domain.sonarqube.Issue.TextRange;
import com.fortify.fprtosonarqube.domain.sonarqube.Issue.TextRange.TextRangeBuilder;
import com.fortify.fprtosonarqube.domain.sonarqube.Rule;
import com.fortify.fprtosonarqube.util.StreamingFvdlParser;
import com.fortify.util.xml.XmlMapperHelper;

public class Main {
	private final String fprFileName;
	private final String outputFileName;
	private Map<String, Node> nodePool = null;
	private String sourceBasePath = null;
	
	public Main(String fprFileName, String outputFileName) {
		this.fprFileName = fprFileName;
		this.outputFileName = outputFileName;
	}

	private Map<String, Node> getNodePool() throws IOException, XMLStreamException {
		if ( nodePool == null ) {
			nodePool = new LinkedHashMap<String, Vulnerability.Node>();
			new StreamingFvdlParser()
					.handler("UnifiedNodePool/Node", reader-> {
						Node node = XmlMapperHelper.getDefaultXmlMapper().readValue(reader, Node.class);
						nodePool.put(node.getId(), node);
					}).parse(fprFileName);
		}
		return nodePool;
	}
	
	private void process() throws FileNotFoundException, IOException, XMLStreamException {
		try (JsonGenerator generator = new JsonFactory().createGenerator(
                        new File(outputFileName)
                        , JsonEncoding.UTF8)) {
			generator.setCodec(new ObjectMapper());
			generator.setPrettyPrinter(new DefaultPrettyPrinter());
			generator.writeStartObject();
			writeIssues(generator);
			writeRules(generator);
			generator.writeEndObject();
		}
	}

	private void writeIssues(final JsonGenerator generator) throws IOException, XMLStreamException {
		generator.writeArrayFieldStart("issues");
		new StreamingFvdlParser()
			.handler("Build/SourceBasePath", reader->sourceBasePath=reader.getElementText())
			.handler("Vulnerabilities/Vulnerability", reader->{
				Vulnerability vuln = XmlMapperHelper.getDefaultXmlMapper().readValue(reader, Vulnerability.class);
				Issue issue = getIssue(vuln);
				if ( issue!=null ) {
					generator.writeObject(issue);
				}
			})
			.parse(fprFileName);
		generator.writeEndArray();
	}
	
	private Issue getIssue(Vulnerability vuln) throws IOException, XMLStreamException {
		Issue issue = null;
		// TODO Add null checks
		Entry entry = vuln.getAnalysisInfo().getUnified().getTrace().getPrimary().getDefaultEntry();
		Node node = entry.getNode();
		if ( node==null && entry.getNodeRef()!=null) {
			node = getNodePool().get(entry.getNodeRef().getId());
		}
		if ( node!= null && node.getSourceLocation()!=null ) {
			issue = Issue.builder()
				.engineId("Fortify")
				.ruleId(vuln.getClassInfo().getClassID())
				.type("VULNERABILITY")
				.severity("BLOCKER") //TODO Map from Fortify
				.primaryLocation(getPrimaryLocation(vuln, node.getSourceLocation())).build();
		}
		return issue;
	}

	private Location getPrimaryLocation(Vulnerability vuln, SourceLocation sourceLocation) {
		return Location.builder()
			.filePath(Paths.get(sourceBasePath, sourceLocation.getPath()).toFile().getAbsolutePath())
			.message("TODO-generate message from abstract")
			// TODO .textRange(getTextRange(sourceLocation))
			.build();
	}

	private TextRange getTextRange(SourceLocation sourceLocation) {
		System.out.println(sourceLocation);
		TextRangeBuilder textRangeBuilder = TextRange.builder()
			.startLine(sourceLocation.getLine()+1)
			.startColumn(sourceLocation.getColStart());
		if ( sourceLocation.getLineEnd()!=null && sourceLocation.getLineEnd()>sourceLocation.getLine()) {
			textRangeBuilder.endLine(sourceLocation.getLineEnd());
		}
		if ( sourceLocation.getColEnd()!=null && sourceLocation.getColEnd()>sourceLocation.getColStart()) {
			textRangeBuilder.endColumn(sourceLocation.getColEnd());
		}
		return textRangeBuilder.build();
	}

	private void writeRules(final JsonGenerator generator) throws IOException, XMLStreamException {
		generator.writeArrayFieldStart("rules");
		new StreamingFvdlParser()
			.handler("Description", reader->{
				Description desc = XmlMapperHelper.getDefaultXmlMapper().readValue(reader, Description.class);
				Rule rule = getRule(desc);
				if ( rule!=null ) {
					generator.writeObject(rule);
				}
			})
			.parse(fprFileName);
		generator.writeEndArray();
	}

	private Rule getRule(Description desc) {
		return Rule.builder()
			.engineId("Fortify")
			.ruleId(desc.getClassID())
			.name(desc.getClassID())
			// TODO Add recommendations and other elements to description
			.description(desc.getExplanation().replace("<Content>", "").replace("</Content>", ""))
			.severity("BLOCKER")
			.type("VULNERABILITY").build();
	}

	public static void main(String[] args) throws IOException, XMLStreamException {
		if (args.length != 1) {
			System.err.println("Usage: java -jar FprToSonarQube.jar <file.fpr>");
			System.exit(1);
		}
		new Main(args[0], args[0].replace(".fpr", ".json")).process();
	}
}
