// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Serializes objects and reads them back, as a service that deserializes a
// request would, and says who answered: exit status 0 when the java-deserial
// guard refused a class on its deny list and let an ordinary graph through,
// 1 otherwise. The refused class is a stub with the name of a gadget class,
// not a gadget, so a JVM without the guard reads it back and nothing runs.
// On release 17 and newer it also checks that a filter the stream sets
// still applies beside the guard.

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.collections.functors.InvokerTransformer;

public class DeserialRead {
    private static byte[] write(Object object) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(object);
        }
        return bytes.toByteArray();
    }

    /** Reads bytes back, through filter as the stream's own when not null. */
    private static Object read(byte[] bytes, ObjectInputFilter filter) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            if (filter != null) in.setObjectInputFilter(filter);
            return in.readObject();
        }
    }

    private static boolean refused(String what, Object object, ObjectInputFilter filter) throws Exception {
        try {
            read(write(object), filter);
            System.out.println("deserialRead: " + what + ": read back");
            return false;
        } catch (InvalidClassException e) {
            System.out.println("deserialRead: " + what + ": refused: " + e.getMessage());
            return true;
        }
    }

    private static int release() {
        String spec = System.getProperty("java.specification.version");
        return Integer.parseInt(spec.startsWith("1.") ? spec.substring(2) : spec);
    }

    public static void main(String[] args) throws Exception {
        boolean ok = refused("gadget class", new InvokerTransformer(), null);
        List<Object> list = new ArrayList<>();
        list.add(new InvokerTransformer());
        ok &= refused("gadget class inside a list", list, null);

        Map<String, List<Integer>> graph = new HashMap<>();
        graph.put("a", new ArrayList<>(List.of(1, 2, 3)));
        ok &= !refused("ordinary graph", graph, null);

        if (release() >= 17) {
            // A stream filter that refuses Date and decides nothing else.
            ObjectInputFilter own = info -> info.serialClass() == Date.class
                    ? ObjectInputFilter.Status.REJECTED : ObjectInputFilter.Status.UNDECIDED;
            ok &= refused("class the stream's filter refuses", new Date(0), own);
            ok &= refused("gadget class beside the stream's filter", new InvokerTransformer(), own);
            ok &= !refused("ordinary graph beside the stream's filter", graph, own);
        }
        System.out.println(ok ? "deserialRead: refused by the guard" : "deserialRead: no guard");
        System.exit(ok ? 0 : 1);
    }
}
