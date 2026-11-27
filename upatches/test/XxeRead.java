// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Parses a document whose external entity names a local file, as an XML
// external entity injection has a parser do, with the DOM, SAX and StAX
// parsers of the JDK, and says what each did: exit status 0 when
// javax.xml.accessExternalDTD, the property the java-xxe guard sets, kept
// every parser from the file and a document without an external entity
// still parsed, 1 otherwise. That shows what the property does, not who
// set it: run this without the agent and with it. The file is one this
// program writes, so a JVM without the guard reads nothing of the host's.

import java.io.File;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;

public class XxeRead {
    private static final String CONTENT = "xxeRead: content of the file";
    // The JDK names the property in the error of a fetch it refused for it.
    private static final String PROPERTY = "accessExternalDTD";

    private interface Parse {
        String text(String xml) throws Exception;
    }

    private static String dom(String xml) throws Exception {
        return DocumentBuilderFactory.newInstance().newDocumentBuilder()
                .parse(new InputSource(new StringReader(xml))).getDocumentElement().getTextContent();
    }

    private static String sax(String xml) throws Exception {
        final StringBuilder text = new StringBuilder();
        SAXParserFactory.newInstance().newSAXParser().parse(new InputSource(new StringReader(xml)),
                new DefaultHandler() {
                    @Override
                    public void characters(char[] ch, int start, int length) {
                        text.append(ch, start, length);
                    }
                });
        return text.toString();
    }

    private static String stax(String xml) throws Exception {
        XMLStreamReader reader = XMLInputFactory.newInstance().createXMLStreamReader(new StringReader(xml));
        try {
            StringBuilder text = new StringBuilder();
            while (reader.hasNext()) {
                if (reader.next() == XMLStreamConstants.CHARACTERS) text.append(reader.getText());
            }
            return text.toString();
        } finally {
            reader.close();
        }
    }

    private static boolean refused(String what, Parse parser, String xml) {
        try {
            String text = parser.text(xml);
            System.out.println("xxeRead: " + what + ": "
                    + (text.contains(CONTENT) ? "read the file" : "parsed without the file"));
        } catch (Exception e) {
            if (String.valueOf(e.getMessage()).contains(PROPERTY)) {
                System.out.println("xxeRead: " + what + ": refused, " + PROPERTY + " allows no fetch");
                return true;
            }
            System.out.println("xxeRead: " + what + ": failed otherwise: " + e);
        }
        return false;
    }

    private static boolean parsed(String what, Parse parser, String xml) {
        try {
            if (parser.text(xml).contains(CONTENT)) {
                System.out.println("xxeRead: " + what + ": parsed");
                return true;
            }
            System.out.println("xxeRead: " + what + ": parsed without its entity");
        } catch (Exception e) {
            System.out.println("xxeRead: " + what + ": failed: " + e);
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        File target = File.createTempFile("xxeRead", ".txt");
        boolean ok = true;
        try {
            Files.write(target.toPath(), CONTENT.getBytes(StandardCharsets.UTF_8));
            String external = "<!DOCTYPE r [<!ENTITY e SYSTEM \"" + target.toURI() + "\">]><r>&e;</r>";
            String internal = "<!DOCTYPE r [<!ENTITY e \"" + CONTENT + "\">]><r>&e;</r>";
            ok &= refused("DOM, external entity", XxeRead::dom, external);
            ok &= refused("SAX, external entity", XxeRead::sax, external);
            ok &= refused("StAX, external entity", XxeRead::stax, external);
            // An entity the document defines itself is not a fetch: the
            // property must leave it alone.
            ok &= parsed("DOM, internal entity", XxeRead::dom, internal);
        } finally {
            target.delete();
        }
        System.exit(ok ? 0 : 1);
    }
}
