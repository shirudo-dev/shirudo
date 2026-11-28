// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.security.rasp;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

/**
 * A small SQL lexer that finds structural injection in a statement's text.
 *
 * <p>It knows where string literals, quoted identifiers and comments are,
 * so a pattern inside a literal is data and not a finding. Outside literals
 * it reports:
 *
 * <ul>
 * <li>a comment, whatever the dialect: {@code --}, {@code #} or a block
 *     comment anywhere but first or last in the statement, where tracing
 *     agents and ORMs put theirs; an injected payload ends the query with
 *     a comment, or uses a block comment as white space;
 * <li>a second statement after a {@code ;};
 * <li>an {@code OR} whose operands are literals that compare true, such as
 *     {@code OR 1=1}, {@code OR 'a'='a'}, {@code OR(2>1)} or
 *     {@code OR TRUE}. An {@code AND} tautology is left alone: query
 *     builders emit {@code AND 1=1};
 * <li>a comparison of two string literals that is true, wherever it stands,
 *     since no application compares two string constants.
 * </ul>
 *
 * <p>This is a mitigation for concatenated SQL, not a parser of any one
 * dialect. A query built with bind parameters carries none of this and
 * passes. It does not see a payload that needs none of the above, such as a
 * {@code UNION SELECT} appended to a numeric condition with no tautology.
 *
 * <p>The class depends on nothing outside the JDK, so it runs and is tested
 * without the agent.
 */
public final class SqlGuard {

    private enum Kind { WORD, NUMBER, STRING, QUOTED, OP, LPAREN, RPAREN, SEMI }

    private static final class Token {
        final Kind kind;
        final String text;

        Token(Kind kind, String text) {
            this.kind = kind;
            this.text = text;
        }
    }

    private SqlGuard() {
    }

    /**
     * The reason {@code sql} looks injected, or {@code null} when it does
     * not.
     */
    public static String check(String sql) {
        if (sql == null) {
            return null;
        }

        List<Token> tokens = new ArrayList<>();
        String comment = lex(sql, tokens);
        if (comment != null) {
            return comment;
        }
        return structure(tokens);
    }

    /**
     * Fills {@code out} with the tokens of {@code sql}; the description of
     * the first comment, if the text has one.
     */
    private static String lex(String sql, List<Token> out) {
        int n = sql.length();
        int i = 0;

        while (i < n) {
            char c = sql.charAt(i);

            if (Character.isWhitespace(c)) {
                i++;
            } else if (c == '-' && i + 1 < n && sql.charAt(i + 1) == '-') {
                return "comment \"--\"";
            } else if (c == '#') {
                return "comment \"#\"";
            } else if (c == '/' && i + 1 < n && sql.charAt(i + 1) == '*') {
                int end = sql.indexOf("*/", i + 2);

                if (end < 0) {
                    return "comment \"/*\" that does not end";
                }
                end += 2;
                // Tracing agents, ORMs and sqlcommenter tag a statement with
                // a block comment at its start or end, and refusing those
                // would refuse all their traffic. One anywhere else, such
                // as "x'/**/OR/**/1=1", is how a payload hides white space.
                if (!out.isEmpty() && !onlyWhitespace(sql, end)) {
                    return "comment \"/*\" inside the statement";
                }
                i = end;
            } else if (c == '\'') {
                StringBuilder text = new StringBuilder();

                i = readQuoted(sql, i, '\'', text);
                out.add(new Token(Kind.STRING, text.toString()));
            } else if (c == '"' || c == '`') {
                i = readQuoted(sql, i, c, null);
                out.add(new Token(Kind.QUOTED, ""));
            } else if (c == '[') {
                int close = sql.indexOf(']', i + 1);
                i = close < 0 ? n : close + 1;
                out.add(new Token(Kind.QUOTED, ""));
            } else if (c == ';') {
                out.add(new Token(Kind.SEMI, ";"));
                i++;
            } else if (c == '(') {
                out.add(new Token(Kind.LPAREN, "("));
                i++;
            } else if (c == ')') {
                out.add(new Token(Kind.RPAREN, ")"));
                i++;
            } else if (isOperatorChar(c)) {
                int start = i;
                while (i < n && isOperatorChar(sql.charAt(i))) {
                    i++;
                }
                out.add(new Token(Kind.OP, sql.substring(start, i)));
            } else if (isWordChar(c) || c == '.') {
                int start = i;
                while (i < n && (isWordChar(sql.charAt(i)) || sql.charAt(i) == '.')) {
                    i++;
                }
                String word = sql.substring(start, i);
                out.add(new Token(isNumber(word) ? Kind.NUMBER : Kind.WORD, word));
            } else {
                // A character no rule needs, such as ',' or '*'.
                out.add(new Token(Kind.OP, String.valueOf(c)));
                i++;
            }
        }
        return null;
    }

    private static boolean onlyWhitespace(String sql, int from) {
        for (int i = from; i < sql.length(); i++) {
            if (!Character.isWhitespace(sql.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * The index after the literal that starts at {@code start} with
     * {@code quote}, with its text, unescaped, appended to {@code text} when
     * that is not null. A doubled quote is an escaped quote, and a literal
     * with no end runs to the end of the text.
     */
    private static int readQuoted(String sql, int start, char quote,
                                  StringBuilder text) {
        int n = sql.length();
        int i = start + 1;

        while (i < n) {
            char c = sql.charAt(i);

            if (c == quote) {
                if (i + 1 < n && sql.charAt(i + 1) == quote) {
                    if (text != null) {
                        text.append(quote);
                    }
                    i += 2;
                    continue;
                }
                return i + 1;
            }
            if (text != null) {
                text.append(c);
            }
            i++;
        }
        return n;
    }

    private static boolean isOperatorChar(char c) {
        return c == '=' || c == '<' || c == '>' || c == '!';
    }

    private static boolean isWordChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '$' || c == '@';
    }

    private static boolean isNumber(String word) {
        boolean digit = false;

        for (int i = 0; i < word.length(); i++) {
            char c = word.charAt(i);
            if (c >= '0' && c <= '9') {
                digit = true;
            } else if (c != '.') {
                return false;
            }
        }
        return digit && word.indexOf('.') == word.lastIndexOf('.');
    }

    private static String structure(List<Token> tokens) {
        int n = tokens.size();

        for (int i = 0; i < n; i++) {
            Token t = tokens.get(i);

            if (t.kind == Kind.SEMI && i + 1 < n && !onlySemicolons(tokens, i)) {
                return "more than one statement";
            }
            if (t.kind == Kind.WORD && t.text.equalsIgnoreCase("or")
                    && orTautology(tokens, i + 1)) {
                return "OR with a condition that is always true";
            }
            // No application compares two string constants; a payload does
            // to make a WHERE true after a UNION or an AND as well.
            if (t.kind == Kind.STRING && i + 2 < n
                    && tokens.get(i + 1).kind == Kind.OP
                    && tokens.get(i + 2).kind == Kind.STRING
                    && compares(t, tokens.get(i + 1).text, tokens.get(i + 2))) {
                return "comparison of two string literals that is always true";
            }
        }
        return null;
    }

    private static boolean onlySemicolons(List<Token> tokens, int from) {
        for (int i = from; i < tokens.size(); i++) {
            if (tokens.get(i).kind != Kind.SEMI) {
                return false;
            }
        }
        return true;
    }

    /** Whether the tokens from {@code at} are {@code [(...] lit op lit}. */
    private static boolean orTautology(List<Token> tokens, int at) {
        int n = tokens.size();
        int i = at;

        while (i < n && tokens.get(i).kind == Kind.LPAREN) {
            i++;
        }
        // OR TRUE, but not OR TRUE = x, which compares something.
        if (i < n && tokens.get(i).kind == Kind.WORD
                && tokens.get(i).text.equalsIgnoreCase("true")
                && (i + 1 >= n || tokens.get(i + 1).kind != Kind.OP)) {
            return true;
        }
        if (i + 2 >= n) {
            return false;
        }
        Token left = tokens.get(i);
        Token op = tokens.get(i + 1);
        Token right = tokens.get(i + 2);

        if (!isLiteral(left) || op.kind != Kind.OP || !isLiteral(right)) {
            return false;
        }
        return compares(left, op.text, right);
    }

    private static boolean isLiteral(Token t) {
        return t.kind == Kind.NUMBER || t.kind == Kind.STRING;
    }

    private static boolean compares(Token left, String op, Token right) {
        int cmp;

        if (left.kind == Kind.NUMBER || right.kind == Kind.NUMBER) {
            // A number against a string compares as numbers, as MySQL does;
            // a string that is not one never equals it.
            BigDecimal a = number(left);
            BigDecimal b = number(right);

            if (a == null || b == null) {
                return op.equals("<>") || op.equals("!=");
            }
            cmp = a.compareTo(b);
        } else {
            cmp = left.text.compareToIgnoreCase(right.text);
        }

        switch (op) {
        case "=":
        case "==":
            return cmp == 0;
        case "<>":
        case "!=":
            return cmp != 0;
        case "<":
            return cmp < 0;
        case ">":
            return cmp > 0;
        case "<=":
            return cmp <= 0;
        case ">=":
            return cmp >= 0;
        default:
            return false;
        }
    }

    private static BigDecimal number(Token t) {
        try {
            return new BigDecimal(t.text.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
