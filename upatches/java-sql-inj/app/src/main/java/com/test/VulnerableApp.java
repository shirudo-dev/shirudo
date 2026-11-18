// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

package com.test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.ResultSet;

public class VulnerableApp {
    public static void main(String[] args) {
        // Read input from the command line argument, or use a default malicious payload
        String userInput = (args.length > 0) ? args[0] : "admin' OR 1=1";

        System.out.println("[App] Starting application...");
        System.out.println("[App] Simulating HTTP Request payload: " + userInput);

        String url = "jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1";

        try (Connection conn = DriverManager.getConnection(url, "sa", "")) {
            // Setup a mock schema for testing
            try (Statement setupStmt = conn.createStatement()) {
                setupStmt.execute("CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(255), password VARCHAR(255))");
                setupStmt.execute("INSERT INTO users VALUES (1, 'admin', 'super-secret-pass')");
            }

            // Vulnerable pattern: Concatenating input directly into raw SQL
            String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
            System.out.println("[App] Preparing to call statement.executeQuery()...");

            try (Statement statement = conn.createStatement();
                 ResultSet rs = statement.executeQuery(query)) { // RASP hooks into this specific call

                System.out.println("[App] Query completed successfully! Result rows:");
                while (rs.next()) {
                    System.out.println("  -> Found User: " + rs.getString("username"));
                }
            }

        } catch (SecurityException e) {
            System.err.println("\n[App] !!! BLOCK ACTION TRIGGERED !!!");
            System.err.println("[App] RASP safely aborted execution: " + e.getMessage() + "\n");
        } catch (Exception e) {
            System.err.println("[App] Runtime Database Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
