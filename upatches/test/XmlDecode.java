// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Decodes synthetic documents that ask java.beans.XMLDecoder to do what
// an attacker's document does, and says who answered: exit status 0 when
// the java-xmldecoder guard refused each one and the effect did not
// happen, and when the documents that XMLEncoder wrote for ordinary
// objects decoded to equal objects, 1 otherwise. The effect of an attack
// is a marker file that this program owns or a field of a class of its
// own; no document starts a process. Run it without the agent, where
// each attack prints "no guard, it ran", and with it. With the argument
// "wait" it decodes one ordinary document, prints "xmlDecode: ready" and
// waits for a line on standard input before it goes on, so that an agent
// can attach to it in between.

import java.beans.ExceptionListener;
import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import javax.xml.parsers.SAXParserFactory;

public class XmlDecode {
    private static final String REFUSAL = "com.shirudo.xmldecoderguard.RefusedException";

    /** A class with a public static field, which a document must not write. */
    public static class Flag {
        public static String value = "unset";
    }

    /** A bean with a property, as an application archives one. */
    public static class Bean {
        private String name;

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        @Override
        public boolean equals(Object o) { return o instanceof Bean && Objects.equals(name, ((Bean) o).name); }

        @Override
        public int hashCode() { return Objects.hashCode(name); }
    }

    // The first exception that the decoder handed to its listener.
    private static Exception reported;

    private static final ExceptionListener LISTENER = e -> {
        if (reported == null) reported = e;
    };

    private static String xml(File file) {
        return file.getPath().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private interface Route {
        Object decode(byte[] xml) throws Exception;
    }

    private static Object read(byte[] xml) {
        return new XMLDecoder(new ByteArrayInputStream(xml), null, LISTENER).readObject();
    }

    // A SAX parser of the application's own, which drives the handler that
    // XMLDecoder hands out and so never enters DocumentHandler.parse.
    private static Object parse(byte[] xml) throws Exception {
        SAXParserFactory.newInstance().newSAXParser()
                .parse(new ByteArrayInputStream(xml), XMLDecoder.createHandler(null, LISTENER, null));
        return null;
    }

    // Whether the guard's exception, by its class name, heads the chain that was thrown.
    private static boolean refusal(Throwable t) {
        for (int hops = 0; t != null && hops < 8; hops++, t = t.getCause()) {
            if (t.getClass().getName().equals(REFUSAL)) return true;
        }
        return false;
    }

    private static int refused;
    // The effect says, of the value that the decode gave, whether the attack worked.
    private static boolean attack(String id, Route route, String xml, Predicate<Object> effect) {
        Throwable thrown = null;
        Object value = null;
        reported = null;
        try {
            value = route.decode(xml.getBytes(StandardCharsets.UTF_8));
        } catch (Throwable t) {
            thrown = t;
        }
        boolean ran = effect.test(value);
        String answer = ran ? "no guard, it ran" : "no guard, no effect: " + (thrown != null ? thrown : reported);
        if (refusal(thrown)) answer = ran ? "refused, but it ran" : "refused by the guard";
        if (refusal(thrown)) refused++;
        System.out.println("xmlDecode: " + id + ": " + answer);
        return answer.equals("refused by the guard");
    }

    private static byte[] encode(Object value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (XMLEncoder encoder = new XMLEncoder(out)) {
            encoder.writeObject(value);
        }
        return out.toByteArray();
    }

    private static boolean ordinary(String id, Object value) {
        String answer;
        reported = null;
        try {
            Object decoded = read(encode(value));
            answer = reported != null ? "the decoder reported " + reported
                    : value.equals(decoded) ? "decoded" : "decoded to " + decoded;
        } catch (RuntimeException e) {
            answer = "failed: " + e;
        }
        System.out.println("xmlDecode: " + id + ": " + answer);
        return answer.equals("decoded");
    }

    public static void main(String[] args) throws Exception {
        File dir = Files.createTempDirectory("xmlDecode").toFile();
        boolean ok = true;
        if (args.length == 1 && args[0].equals("wait")) {
            read(encode(new ArrayList<>(Arrays.asList("a", "b"))));
            System.out.println("xmlDecode: ready");
            System.in.read();
        }
        try {
            File call = new File(dir, "call");
            File made = new File(dir, "new");
            File viaParser = new File(dir, "parser");
            String create = "<java><object class=\"java.io.File\"><string>%s</string>"
                    + "<void method=\"createNewFile\"/></object></java>";
            ok &= attack("method-call", XmlDecode::read, String.format(create, xml(call)), v -> call.exists());
            // FileWriter creates its file when it is constructed, whatever is called on it after.
            ok &= attack("new-method", XmlDecode::read,
                    "<java><new class=\"java.io.FileWriter\"><string>" + xml(made) + "</string>"
                    + "<method name=\"close\"/></new></java>", v -> made.exists());
            ok &= attack("field-write", XmlDecode::read,
                    "<java><field class=\"XmlDecode$Flag\" name=\"value\"><string>changed</string></field></java>",
                    v -> Flag.value.equals("changed"));
            ok &= attack("field-read", XmlDecode::read,
                    "<java><object class=\"java.lang.System\" field=\"out\"/></java>", v -> v == System.out);
            ok &= attack("create-handler", XmlDecode::parse, String.format(create, xml(viaParser)),
                    v -> viaParser.exists());

            Bean bean = new Bean();
            bean.setName("widget");
            Map<String, Object> map = new HashMap<>();
            map.put("one", 1);
            ok &= ordinary("list", new ArrayList<>(Arrays.asList("a", "b")));
            ok &= ordinary("map", map);
            ok &= ordinary("bean", bean);
        } finally {
            for (File f : dir.listFiles()) f.delete();
            dir.delete();
        }
        if (refused == 0) System.out.println("xmlDecode: no attack was refused: this was the unguarded baseline");
        System.exit(ok ? 0 : 1);
    }
}
