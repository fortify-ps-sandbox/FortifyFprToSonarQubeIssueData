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
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.xml.stream.XMLStreamException;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fortify.fprtosonarqube.domain.fvdl.FvdlDescription;
import com.fortify.fprtosonarqube.domain.fvdl.FvdlVulnerability;
import com.fortify.fprtosonarqube.domain.fvdl.FvdlVulnerability.Entry;
import com.fortify.fprtosonarqube.domain.fvdl.FvdlVulnerability.Node;
import com.fortify.fprtosonarqube.domain.fvdl.FvdlVulnerability.SourceLocation;
import com.fortify.fprtosonarqube.domain.sonarqube.SQIssue;
import com.fortify.fprtosonarqube.domain.sonarqube.SQIssue.Location;
import com.fortify.fprtosonarqube.domain.sonarqube.SQIssue.TextRange;
import com.fortify.fprtosonarqube.domain.sonarqube.SQIssue.TextRange.TextRangeBuilder;
import com.fortify.fprtosonarqube.domain.sonarqube.SQRule;
import com.fortify.fprtosonarqube.util.StreamingFvdlParser;
import com.fortify.util.xml.XmlMapperHelper;

public class FvdlParser {
	private final String fprFileName;
	private final Map<String, String> iidToFolderMap;
	private Map<String, Node> nodePool = null;
	private String sourceBasePath = null;
	
	public FvdlParser(String fprFileName, Map<String, String> iidToFolderMap) {
		this.fprFileName = fprFileName;
		this.iidToFolderMap = iidToFolderMap;
	}

	private Map<String, Node> getNodePool() throws IOException, XMLStreamException {
		if ( nodePool == null ) {
			nodePool = new LinkedHashMap<String, FvdlVulnerability.Node>();
			new StreamingFvdlParser()
					.handler("UnifiedNodePool/Node", reader-> {
						Node node = XmlMapperHelper.getDefaultXmlMapper().readValue(reader, Node.class);
						nodePool.put(node.getId(), node);
					}).parseFpr(fprFileName);
		}
		return nodePool;
	}

	public void parse(final JsonGenerator generator) throws IOException, XMLStreamException {
		writeIssues(generator);
		writeRules(generator);
	}

	private void writeIssues(final JsonGenerator generator) throws IOException, XMLStreamException {
		generator.writeArrayFieldStart("issues");
		if ( !iidToFolderMap.isEmpty() ) {
			new StreamingFvdlParser()
				.handler("Build/SourceBasePath", reader->sourceBasePath=reader.getElementText())
				.handler("Vulnerabilities/Vulnerability", reader->{
					FvdlVulnerability vuln = XmlMapperHelper.getDefaultXmlMapper().readValue(reader, FvdlVulnerability.class);
					SQIssue issue = getSQIssue(vuln);
					if ( issue!=null ) {
						generator.writeObject(issue);
					}
				})
				.parseFpr(fprFileName);
		}
		generator.writeEndArray();
	}
	
	private SQIssue getSQIssue(FvdlVulnerability vuln) throws IOException, XMLStreamException {
		SQIssue issue = null;
		// TODO Add null checks
		String iid = vuln.getInstanceInfo().getInstanceID();
		String folder = iidToFolderMap.get(iid);
		if ( folder!=null ) {
			Entry entry = vuln.getAnalysisInfo().getUnified().getTrace().getPrimary().getDefaultEntry();
			Node node = entry.getNode();
			if ( node==null && entry.getNodeRef()!=null) {
				node = getNodePool().get(entry.getNodeRef().getId());
			}
			if ( node!= null && node.getSourceLocation()!=null ) {
				issue = SQIssue.builder()
					.engineId("Fortify")
					.ruleId(vuln.getClassInfo().getClassID())
					.type("VULNERABILITY")
					.severity(getSeverity(folder))
					.primaryLocation(getPrimaryLocation(vuln, node.getSourceLocation())).build();
			}
		}
		return issue;
	}

	private String getSeverity(String folder) {
		if ( "Critical".equalsIgnoreCase(folder) ) {
			return "CRITICAL";
		} else if ( "High".equalsIgnoreCase(folder) ) {
			return "MAJOR";
		} else if ( "Medium".equalsIgnoreCase(folder) ) {
			return "MINOR";
		} else {
			return "INFO";
		}
	}

	private Location getPrimaryLocation(FvdlVulnerability vuln, SourceLocation sourceLocation) {
		String msg = vuln.getClassInfo().getType();
		if ( StringUtils.isNotBlank(vuln.getClassInfo().getSubtype()) ) {
			msg += ": "+vuln.getClassInfo().getSubtype();
		}
		return Location.builder()
			.filePath(Paths.get(sourceBasePath, sourceLocation.getPath()).toFile().getAbsolutePath())
			.message(msg) // TODO Add/use abstract?
			.textRange(getTextRange(sourceLocation))
			.build();
	}

	private TextRange getTextRange(SourceLocation sourceLocation) {
		System.out.println(sourceLocation);
		TextRangeBuilder textRangeBuilder = TextRange.builder()
			.startLine(sourceLocation.getLine())
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
				FvdlDescription desc = XmlMapperHelper.getDefaultXmlMapper().readValue(reader, FvdlDescription.class);
				SQRule rule = getRule(desc);
				if ( rule!=null ) {
					generator.writeObject(rule);
				}
			})
			.parseFpr(fprFileName);
		generator.writeEndArray();
	}

	private SQRule getRule(FvdlDescription desc) {
		return SQRule.builder()
			.engineId("Fortify")
			.ruleId(desc.getClassID())
			.name(desc.getClassID())
			// TODO Add recommendations and other elements to description
			.description(desc.getExplanation().replace("<Content>", "").replace("</Content>", ""))
			.severity("BLOCKER")
			.type("VULNERABILITY").build();
	}
}
